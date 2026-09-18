# Core Lightning Security Audit — P2P / Loss-of-Funds

**Target:** ElementsProject/lightning @ `c1551c557` (v26.06.6), working tree verified
byte-identical to upstream `origin/master`.

**Scope:** Peer-to-peer protocol code reachable by a malicious network peer
(the node is safe under `--offline`). Focus on paths where peer-controlled
input can cause loss of funds.

**Method:** Full manual audit of `channeld/` (channeld.c, full_channel.c,
commit_tx.c, splice/inflight), `lightningd/` (channel_control.c,
peer_control.c, peer_htlcs.c, closing_control.c, onchain_control.c),
`connectd/`, `openingd/`, `closingd/`, `common/` (onion_decode.c, close_tx.c,
initial_channel.c), plus git-history review of the newest P2P features
(splicing, commitment batching, splice RBF, quiescence, `option_simple_close`).

---

## Executive summary

One **critical, remotely exploitable loss-of-funds vulnerability** was found
in the splice (`option_splice`, **on by default**) `tx_abort` handling, plus
several supporting defects that widen its reach, and a handful of
medium/low issues. The critical bug is a one-token typo that disables a
safety check, combined with an unguarded deletion in `lightningd`, allowing a
malicious peer to make us **discard a splice inflight after we have already
given them our signature for the splice transaction** — after which they can
confirm the splice and steal the entire channel balance unwatched.

| # | Severity | Title | Location |
|---|----------|-------|----------|
| 1 | **CRITICAL — loss of funds** | Dead guard in `check_tx_abort`: peer can `tx_abort` after we signed the splice, inflight (watches + commitment + DB) deleted, funds stolen | `channeld/channeld.c:1887`, `lightningd/channel_control.c:346-363` |
| 2 | High | `handle_splice_abort` deletes unconditionally: no `i_sent_sigs`/`remote_tx_sigs`/state check, missing `return` after mismatch error, unchecked `list_tail` | `lightningd/channel_control.c:346-363` |
| 3 | Medium (DoS) | Missing `return` after `channel_internal_error` in four inflight handlers → NULL-deref crash of `lightningd` on list desync | `lightningd/channel_control.c:669-676, 793-818, 971-993, 1180-1187` |
| 4 | Low | `update_view_from_inflights`: mismatched/swapped conditions leave `lowest_splice_amnt[LOCAL]` unset (self-protection gap during own splice-out) | `channeld/channeld.c:3723-3744` |
| 5 | Info | Verified-safe areas (negative results) | see §6 |

---

## Finding 1 — CRITICAL: `tx_abort` after our signature deletes the signed splice inflight → total channel theft

### 1.1 Root cause: dead guard in channeld

`check_tx_abort()` is supposed to enforce the splice rule *"tx_abort is not
allowed after I have sent my signature"*. The guard is dead code because it
tests the wrong variable — `inflight` (the accumulator, still `NULL`) instead
of `itr` (the matched inflight):

```c
/* channeld/channeld.c:1872-1896 */
static void check_tx_abort(struct peer *peer, const u8 *msg, struct bitcoin_txid *txid)
{
	struct inflight *inflight;
	...
	inflight = NULL;
	for (size_t i = 0; txid && i < tal_count(peer->splice_state->inflights); i++) {
		struct inflight *itr = peer->splice_state->inflights[i];
		if (!bitcoin_txid_eq(&itr->outpoint.txid, txid))
			continue;
		if (have_i_signed_inflight(peer, inflight)) {     /* <-- BUG: `inflight` is NULL here,
		                                                        should be `itr` */
			peer_failed_err(peer->pps, &peer->channel_id, "tx_abort"
				        " is not allowed after I have sent my"
				        " signature. ...");
		}
		inflight = itr;                                   /* assigned only AFTER the check */
	}
```

`have_i_signed_inflight()` (`channeld/channeld.c:1775-1794`) begins with
`if (!inflight || !inflight->psbt) return false;`, so with `inflight == NULL`
it always returns false and the `peer_failed_err` can **never fire**. The
abort is then accepted regardless of whether we already signed:

```c
	...
	status_info("Send ack of tx_abort");
	peer_write(peer->pps, take(towire_tx_abort(NULL, &peer->channel_id, NULL)));
	...
	wire_sync_write(MASTER_FD,
			take(towire_channeld_splice_abort(NULL, false,
			                                  inflight ? &inflight->outpoint : NULL,
			                                  ...)));
	exit(0);
```

The contrast with our *own* abort path proves the intent — it does check
correctly:

```c
/* channeld/channeld.c:1943-1946 */
if (inflight && inflight->i_sent_sigs)
	peer_failed_err(peer->pps, &peer->channel_id,
		      "I needed to abort a splice where I have already"
		      " sent my signatures");
```

Only the **peer-initiated** direction is broken — exactly the
attacker-controlled direction.

### 1.2 Master deletes the signed inflight with no safety checks

On receipt of `channeld_splice_abort` with a non-NULL outpoint,
`lightningd` deletes the inflight unconditionally:

```c
/* lightningd/channel_control.c:346-363 */
if (outpoint) {
	inflight = list_tail(&channel->inflights, struct channel_inflight, list);

	if (!bitcoin_outpoint_eq(outpoint, &inflight->funding->outpoint))
		channel_internal_error(channel, "abort outpoint %s does not"
				       " match ours %s", ...);   /* no return! */

	wallet_inflight_del(ld->wallet, channel, inflight);
	tal_free(inflight);
}
```

There is no check of `inflight->i_sent_sigs`, `inflight->remote_tx_sigs`, or
the channel state (`CHANNELD_AWAITING_SPLICE`). Deleting the inflight
destroys, in one stroke:

- **The watch on the new funding output** — `watch_splice_inflight()`
  (`channel_control.c:758-775`) registers `watch_scriptpubkey(inflight, ...)`
  parented on the inflight object; `tal_free(inflight)` removes it from the
  topology (`lightningd/watch.c:98-101`), same for the blockdepth watch
  (`channel_control.c:752`).
- **`inflight->last_tx`** — the peer's commitment transaction for the *new*
  funding, i.e. the only transaction we could use to respond on-chain to a
  unilateral close of the spliced channel.
- **The DB row** (`wallet_inflight_del`, `wallet/wallet.c:1556-1570`) — after
  a restart the inflight is gone entirely.

### 1.3 What the peer already holds at that moment

In the splice flow, the victim's funding signature for the splice transaction
is handed to the peer in `tx_signatures`:

```c
/* channeld/channeld.c:3915-3928 */
inflight->i_sent_sigs = send_signature;
if (do_i_sign_first(peer, current_psbt, our_role, inflight->force_sign_first)
	&& send_signature) {
	msg = towire_channeld_update_inflight(NULL, current_psbt, NULL, NULL,
	                                      inflight->locked_scid,
	                                      inflight->i_sent_sigs);
	wire_sync_write(MASTER_FD, take(msg));            /* master: AWAITING_SPLICE + watch */
	msg = towire_channeld_splice_sending_sigs(tmpctx, &final_txid);
	wire_sync_write(MASTER_FD, take(msg));

	peer_write(peer->pps, sigmsg);                    /* <-- our SIGHASH_ALL signature to peer */
}
```

The signature is a plain SIGHASH_ALL ECDSA signature on the 2-of-2 funding
input, obtained from the HSM (`towire_hsmd_sign_splice_tx`,
`channeld.c:3874-3882`). Once the peer has it, they can complete and publish
the splice transaction at any time using their own key — no further
cooperation from us is needed.

The vulnerable receive point is immediately after:

```c
/* channeld/channeld.c:3949-3956 */
} else {
	status_debug("Splice: Awaiting signature message");
	msg = peer_read(tmpctx, peer->pps);            /* peer sends tx_abort instead of
	                                                  tx_signatures */
}
type = fromwire_peektype(msg);
check_tx_abort(peer, msg, &inflight->outpoint.txid);   /* dead guard -> abort accepted */
```

The **reconnect variant** is equally exploitable — the reestablish read loop
passes the live inflight txid to the same broken check, regardless of
`i_sent_sigs`:

```c
/* channeld/channeld.c:5854-5860 */
do {
	clean_tmpctx();
	msg = peer_read(tmpctx, peer->pps);
	check_tx_abort(peer, msg,
		       inflight ? &inflight->outpoint.txid : NULL);
} while (handle_peer_error_or_warning(peer->pps, msg) || ...);
```

### 1.4 Full attack chain (all steps peer-controlled)

Preconditions: `option_splice` negotiated — **enabled by default** in this
version (`lightningd/options.c`, splicing no longer requires
`--experimental-splicing`). No other precondition. The victim need not be
the splice initiator (the reconnect variant works regardless of sign order;
the direct variant needs the victim to sign first, which happens whenever
the victim is the splice initiator or accepter with `force_sign_first`).

1. Attacker opens/has a channel with the victim, quiesces it (`stfu`), and
   negotiates a splice (`splice_init`/`splice_ack`, PSBT interactive flow,
   `commitment_signed` exchanged). Splice amount and balance checks all pass
   normally — the splice is entirely legitimate at this point.
2. Commitments are exchanged and the victim sends `tx_signatures`, giving
   the attacker its SIGHASH_ALL signature for the splice funding input. The
   victim's `lightningd` is now in `CHANNELD_AWAITING_SPLICE` and is watching
   the new funding output (`handle_splice_sending_sigs` →
   `watch_splice_inflight`, `channel_control.c:818`).
3. **Attacker sends `tx_abort` instead of its `tx_signatures`** (or
   disconnects, reconnects, and sends `tx_abort` as the first post-
   reestablish message).
4. Due to the dead guard (1.1), channeld acks the abort and reports
   `channeld_splice_abort(did_i_abort=false, &inflight->outpoint, ...)` to
   master.
5. Master (1.2) deletes the inflight: funding-output watch, blockdepth
   watch, `last_tx` (the attacker's commitment for the new funding), and the
   DB row. Master restarts channeld; channel returns to `CHANNELD_NORMAL`
   against the *old* funding.
6. **Attacker broadcasts the fully-signed splice tx** (its key + our
   signature). It confirms, spending the old funding output.
7. `funding_spent` (`lightningd/peer_control.c:2496-2527`) matches **no**
   inflight (deleted) → falls through to `onchaind_funding_spent`
   (`lightningd/onchain_control.c:1771`), which misinterprets the splice tx
   as a unilateral close of the *old* channel and starts onchaind watching
   outputs of the old `channel->last_tx` — irrelevant now.
8. The **new funding output is completely unwatched and we hold no
   commitment tx for it**. The attacker broadcasts its own commitment
   transaction spending the new funding and takes **100% of the channel
   funds** (both balances, plus any wallet UTXOs the victim spliced in).
   Nothing on the victim side reacts; after a restart the inflight is gone
   from the DB — unrecoverable.

### 1.5 Why this matches the engagement brief

- **P2P:** triggered purely by wire messages from a malicious peer
  (`stfu`, `splice_init`, ..., `tx_signatures` from us, `tx_abort` from them).
- **Loss of funds:** total, deterministic theft of the channel value
  (plus any spliced-in UTXOs).
- **Safe with `--offline`:** no peer, no splice negotiation, no `tx_abort`.
- **Default-on:** splicing is enabled by default in this version, so any
  node with a public port and at least one funded channel is exposed.

### 1.6 Recommended fix

1. `channeld/channeld.c:1887` — one-token fix:
   ```c
   if (have_i_signed_inflight(peer, itr)) {
   ```
2. Defense in depth, `lightningd/channel_control.c:346-363` — refuse the
   deletion when it is unsafe:
   ```c
   if (outpoint) {
	inflight = list_tail(&channel->inflights, struct channel_inflight, list);
	if (!inflight) { channel_internal_error(...); return; }
	if (!bitcoin_outpoint_eq(outpoint, &inflight->funding->outpoint)) {
		channel_internal_error(...);
		return;                     /* <-- missing today */
	}
	if (inflight->i_sent_sigs || inflight->remote_tx_sigs
	    || channel->state == CHANNELD_AWAITING_SPLICE) {
		/* We already signed (or hold their signature for) this splice:
		 * an abort now is a protocol violation, not a rollback. */
		channel_fail_permanent(...);
		return;
	}
	wallet_inflight_del(ld->wallet, channel, inflight);
	tal_free(inflight);
   }
   ```
   (Even with the channeld guard fixed, master must not trust channeld.)

---

## Finding 2 — HIGH: `handle_splice_abort` deletion is unconditional and unvalidated

(Same code as §1.2; listed separately because it is independently wrong and
remains dangerous even if the channeld typo is fixed.)

`lightningd/channel_control.c:346-363`:

1. **No signature/state check before deletion** — `i_sent_sigs`,
   `remote_tx_sigs`, and `CHANNELD_AWAITING_SPLICE` are all ignored. This is
   the funds-loss enabler for Finding 1.
2. **Missing `return` after the mismatch `channel_internal_error`** — on an
   outpoint mismatch the code logs an internal error and then **deletes the
   tail inflight anyway**, i.e. potentially a *different, possibly signed*
   RBF inflight than the one being aborted. (Note `channel_internal_error`
   force-closes the channel but does not stop this handler; the subsequent
   `wallet_inflight_del`/`tal_free` run regardless.)
3. **Unchecked `list_tail`** — if channeld ever reports an abort with a
   non-NULL outpoint while the inflight list is empty, `&inflight->funding->outpoint`
   at line 352 is a NULL dereference (whole-daemon crash).

---

## Finding 3 — MEDIUM (DoS): missing `return` after `channel_internal_error` in inflight handlers

Four handlers follow the pattern "look up inflight by txid → internal error
if missing → **keep going and dereference NULL**":

| Handler | Lookup + error (no return) | Crash point |
|---|---|---|
| `handle_splice_confirmed_signed` | `channel_control.c:669-673` | `675: inflight->remote_tx_sigs = true;` + `676: wallet_inflight_save(...)` |
| `handle_splice_sending_sigs` | `channel_control.c:793-797` | `818: watch_splice_inflight(ld, inflight)` → `762-765: inflight->channel` deref |
| `handle_update_inflight` | `channel_control.c:971-976` (and `978-982`) | `985: tal_free(inflight->last_tx)`, `992: inflight->locked_scid` |
| `handle_peer_splice_locked` | `channel_control.c:1180-1184` | `1186-1187: &inflight->funding->outpoint` |

These crash the whole `lightningd` — every channel stops being watched until
restart (availability hazard; not direct theft). They require a
master/channeld inflight-list desync; Finding 2's wrong-tail deletion
creates exactly such desyncs (it deletes an inflight channeld still knows
about, before channeld exits), so the two compound.

---

## Finding 4 — LOW: `update_view_from_inflights` mismatched conditions

`channeld/channeld.c:3723-3744`:

```c
if (splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE])
	peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL] = splice_amnt;   /* cond != write */
...
if (remote_splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL])
	peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE] = remote_splice_amnt;  /* cond != write */
```

Consequences (traced through `get_room_above_reserve`,
`channeld/full_channel.c:418-467`):

- The `lowest_splice_amnt[LOCAL]` slots are never set (the only writes that
  could set them are guarded by conditions that effectively never fire), so
  while **we** have a splice-out inflight pending, our own balance is not
  conservatively reduced when adding HTLCs — a self-protection gap; we can
  overcommit ourselves into fees.
- The remote-side tracking (`view[LOCAL].lowest_splice_amnt[REMOTE]`, line
  3738) does work, so a peer cannot use this to inflate their spendable
  balance at our expense; hence Low, not High.
- Also note `splice_amnt` is initialized from
  `inflights[i]->amnt.satoshis` (the *total* new funding) rather than the
  relative `inflights[i]->splice_amnt` used everywhere else — likely a
  copy-paste artifact, and the reason the `[LOCAL]` conditions never fire.

---

## Finding 5 — INFO: recent fixes in this tree (context)

The audit surface was narrowed by fixes already present at this commit:

- `96f026ecc` — `onion_decode.c` blinded-forward `fee_proportional_millionths`
  overflow (SIGFPE) — fixed here.
- `eafdd9386` — zero `next_commitment_number` on advanced channels — fixed here.
- `e081eb3e3` — channeld rejects unexpected `closing_complete`/`closing_sig` — fixed here.
- `f0c702ed8` — connectd websocket header case-insensitivity — fixed here.
- `f2a0fb2c5` — `marginal_feerate()` saturation — fixed here.
- `4b34ad332` — `funding_satoshis` bounded by total supply — fixed here.

## 6. Verified-safe areas (negative results)

- **Commitment validation** (`handle_peer_commit_sig`, `channeld.c:2001-2337`;
  `peer_got_commitsig`, `peer_htlcs.c:2396-2551`): remote commitment
  signatures are verified against a *locally reconstructed* commitment tx
  (our view, per-inflight amounts/pubkeys), HTLC sigs checked per output,
  `hsmd_validate_commitment_tx` consulted; commitment/revocation counters
  enforced; batch `funding_txid` per inflight enforced. A peer cannot make us
  store or accept a forged commitment.
- **Splice lockin** (`check_mutual_splice_locked`, `channeld.c:421-511`):
  requires `remote_locked_txid == locked_txid` where `locked_txid` is only
  set from our own confirmed-depth watch; mismatched `splice_locked` txids
  fail the channel. RBF inflights all spend the same funding outpoint, so
  `wallet_channel_clear_inflights` + the `splice_locked_memonly` race guard
  (`peer_control.c:2508-2521`) are sound.
- **HTLC lifecycle** (`full_channel.c`, `peer_htlcs.c`): linear state-machine
  enforcement blocks double-fulfill/out-of-order transitions;
  `onchain_fulfilled_htlc`/`onchain_failed_our_htlc` guard re-entry.
- **Onion/blinded paths** (`onion_decode.c`, `peer_htlcs.c:1451-1615`): the
  recent `ceil_div` overflow fix is present; blinded failures always return
  `invalid_onion_blinding`; fee/CLTV forward checks (`check_fwd_amount`,
  `check_cltv`) are present on both legacy and blinded paths.
- **Closing negotiation** (`closingd.c`, `closing_control.c:242-281`): close
  txs are built locally and the peer signature is verified against the
  2-of-2 funding wscript; fee-range overlap logic checks bounds; new
  `option_simple_close` code (`common/close_tx.c:113-190`) is
  signature-verified in master before acceptance.
- **connectd** (handshake, framing, multiplex, gossip queries): no
  funds-relevant defects found; message routing to subdaemons is keyed by
  peer identity and connection counter, not peer-controlled data.

---

## 7. Conclusion

The engagement target is **Finding 1**: a malicious peer with any funded
channel to the victim can, with a handful of P2P messages ending in
`tx_abort`, delete a splice inflight after obtaining the victim's signature
for the splice transaction, broadcast the splice, and steal the entire
channel balance from an output the victim no longer watches. It is remotely
triggerable, requires no user action, is available with default settings,
and disappears entirely under `--offline`. The one-line fix in
`channeld/channeld.c:1887` plus the hardening in
`lightningd/channel_control.c:346-363` (Finding 2) close it.
