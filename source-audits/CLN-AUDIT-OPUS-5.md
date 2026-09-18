# Core Lightning — independent P2P attack-surface audit

**Target:** `/Users/juraj/tmp/lightning`, branch `master`, commit `c1551c557`
("Cargo.lock: update dependencies"), clean tree. Nothing in the repo was modified.

**Scope:** bugs that a *malicious remote peer* can trigger over the wire, i.e. bugs
that running with `--offline` would make the node immune to. Priority order:
loss of funds > permanent channel lockup / forced-close griefing > memory safety >
availability. Explicitly out of scope: RPC/plugin/local-operator attacks, bitcoind
trust, and gossip flooding that is merely noisy.

**Method:**
* Read the actual source of `connectd/`, `channeld/`, `closingd/`, `openingd/`,
  `common/` (amount, sphinx, onion decode, commit/close/htlc tx, interactive-tx,
  shutdown script, features/channel types) and the peer-facing parts of
  `lightningd/` (`peer_htlcs.c`, `peer_control.c`, `channel_control.c`,
  `simple_close_control.c`, `htlc_set.c`, `channel.c`).
* Reviewed the recent security-relevant commits for completeness: `96f026ecc`
  (blinded-path forward overflow, Bitcoin Security Council 2026-08-11),
  `f0c702ed8` (websocket header case), `eafdd9386` (zero `next_commitment_number`),
  `f2a0fb2c5` (`marginal_feerate` overflow), `4b34ad332` (funding bounded by
  total supply), `090f4b0e6`, plus the v26.06.x CHANGELOG entries.
* Every candidate finding was actively attacked: I looked for the guard elsewhere
  in the call path that would defeat it. Several candidates were dropped this way
  and are recorded in "Areas audited and found sound" so the negative results are
  visible.
* Explicit distinction is made throughout between **verified in code** and
  **inferred**.

**Severity scale used here**

| Level | Meaning |
|---|---|
| CRITICAL | Remote peer can steal or destroy funds directly. |
| HIGH | Remote peer can permanently lock channel funds, or force a costly unilateral close / destroy the ability to unilaterally close. Memory corruption. |
| MEDIUM | Remote peer can crash or wedge a daemon / channel (availability), or force protocol-level griefing with real but bounded cost. |
| LOW | Robustness / defence-in-depth defect: a guard that does not work, an unchecked arithmetic path, no demonstrated remote impact. |

**Bottom line:** I found **no CRITICAL issue** — no path by which a peer can
directly move satoshis out of a channel in its own favour. I did find two HIGH
issues where a peer chooses an unvalidated `nLockTime` for a transaction we sign
and then rely on, three MEDIUM issues (one remote infinite-loop/OOB in `connectd`,
one spec-mismatch that force-closes a channel, one `channeld` crash-loop), and
four LOW robustness defects, one of which is the *same bug class* as the recently
fixed `96f026ecc` and is therefore an incomplete fix in spirit.

---

## Executive summary

| # | Title | Location | Severity | Fund impact |
|---|---|---|---|---|
| 1 | Closee accepts peer-chosen `locktime` in `closing_complete`; the resulting non-final tx replaces `channel->last_tx` | `closingd/simpleclosed.c:330,415-450`; `lightningd/simple_close_control.c:37-91,143-186` | HIGH | Channel funds unspendable: mutual close cannot confirm and the commitment tx has been overwritten |
| 2 | Splice accepter uses peer-chosen `locktime` verbatim (`/* DTODO validate locktime */`); splice funding tx can be made permanently non-final | `channeld/channeld.c:4338-4339`; `lightningd/peer_control.c:468-483` | HIGH | Channel stuck with an unconfirmable splice; force-close path broadcasts only inflight commitments |
| 3 | `queue_channel_ranges()` reads `scids[off-1]` out of bounds and then spins forever queueing messages | `connectd/queries.c:658-710` (loop at 668-682), `gather_range()` 564-634 | MEDIUM | None directly; connectd wedges and grows unbounded → whole node's networking dies |
| 4 | Closee signs a `closer_scriptpubkey` that master then rejects → `channel_internal_error` → unilateral close | `closingd/simpleclosed.c:352-362,457`; `lightningd/simple_close_control.c:49-89,160-166` | MEDIUM | Forced unilateral close (on-chain fees + CSV delay) after we already handed the peer our signature |
| 5 | Splice interactive-tx without the shared funding input → `status_failed()` in `find_channel_funding_input()` → channeld crash loop | `channeld/channeld.c:1754-1772, 3217-3245, 4341-4347` | MEDIUM | Channel permanently unusable while the peer keeps doing it |
| 6 | `start_batch` `batch_size` is unbounded; peer can make channeld buffer ~4 GB before any processing | `channeld/channeld.c:2423-2440, 2480-2500` | LOW | Memory-exhaustion of channeld |
| 7 | `amount_msat_sub_fee()` computes `1000000 + fee_proportional_millionths` in 32-bit → potential divide-by-zero; `amount_msat_mul_div()` result overflow is unchecked | `common/amount.c:608-620, 656-684` | LOW | Same bug class as `96f026ecc`; SIGFPE if reachable |
| 8 | `channel_update_funding()` negative-balance guards are dead code (`unsigned < 0`) | `common/initial_channel.c:156-182` | LOW | Safety net silently disabled |
| 9 | `update_view_from_inflights()` compares one `lowest_splice_amnt[]` slot and assigns another | `channeld/channeld.c:3723-3746` | LOW | Splice-out reservation min-tracking is wrong across RBF |

---

## Finding 1 — HIGH: `option_simple_close` closee signs and stores a transaction with a peer-chosen `nLockTime`

### Location

`closingd/simpleclosed.c:300-467` (`handle_closing_complete()`),
`common/close_tx.c:112-183` (`create_simple_close_tx()`),
`lightningd/simple_close_control.c:37-91` (`close_tx_check()`),
`lightningd/simple_close_control.c:143-186` (`handle_simpleclosed_closee_broadcast()`),
`lightningd/simple_close_control.c:194-237` (`handle_simpleclosed_complete()`).

### The code

`handle_closing_complete()` pulls `locktime` straight off the wire and never
looks at it again except to hand it to the transaction builder:

```c
/* closingd/simpleclosed.c:317-333 */
	struct amount_sat fee_sat;
	u32 locktime;
	struct tlv_closing_tlvs *tlvs;
	...
	if (!fromwire_closing_complete(tmpctx, msg, &their_cid, &closer_script,
			&closee_script, &fee_sat, &locktime, &tlvs))
		peer_failed_warn(pps, &their_cid,
				 "Bad closing_complete: %s",
				 tal_hex(tmpctx, msg));
```

Every one of the three signing branches passes it through unchanged:

```c
/* closingd/simpleclosed.c:415-450 */
	if (our_output_dust) {
		...
		chosen_tx = make_close_tx(tmpctx, local_wallet_index,
			local_wallet_ext_key, closer_script, NULL, funding_wscript,
			funding, funding_sats, closer_amount, AMOUNT_SAT(0), locktime);
		reply_tlvs->closer_output_only = our_sig(reply_tlvs, chosen_tx,
			remote_fundingkey, &sig, "closer_output_only");
	} else if (tlvs->closer_and_closee_outputs) {
		chosen_tx = make_close_tx(tmpctx, local_wallet_index,
			local_wallet_ext_key, closer_script, closee_script,
			funding_wscript, funding, funding_sats, closer_amount,
			closee_amount, locktime);
		...
```

`create_simple_close_tx()` puts it into the transaction and deliberately uses a
non-final input sequence:

```c
/* common/close_tx.c:126-134 */
	tx = bitcoin_tx(ctx, chainparams, 1, 2, locktime);

	bitcoin_tx_add_input(tx, funding,
		/* RBF-enabled, not final */
		0xFFFFFFFD,
		NULL, funding_sats, NULL, funding_wscript);
```

The tx is then handed to master, which validates the outputs and the peer's
signature but **not** the locktime, and stores it as the channel's last
transaction:

```c
/* lightningd/simple_close_control.c:160-180 */
	const char *err = close_tx_check(tmpctx, channel, tx);
	if (err) { ... return; }
	...
	if (!check_tx_sig(tx, 0, NULL, funding_wscript,
			&channel->channel_info.remote_fundingkey, &sig)) { ... return; }

	channel_set_last_tx(channel, tx, &sig);
	wallet_channel_save(ld->wallet, channel);
```

and `channel_set_last_tx()` is a destructive overwrite of the single slot that
also holds the unilateral commitment transaction:

```c
/* lightningd/channel.c:943-951 */
void channel_set_last_tx(struct channel *channel,
			 struct bitcoin_tx *tx,
			 const struct bitcoin_signature *sig)
{
	assert(tx->chainparams);
	channel->last_sig = *sig;
	tal_free(channel->last_tx);
	channel->last_tx = tal_steal(channel, tx);
}
```

Both the cooperative and the unilateral drop-to-chain paths broadcast
`channel->last_tx` (`lightningd/peer_control.c:480-483`).

### Why it is a bug

`nLockTime` is entirely under the closer's control and CLN performs no sanity
check on it. With `nSequence == 0xFFFFFFFD` on the only input, an `nLockTime`
above the current height (or above the current median time, for values
`>= 500000000`) makes the transaction **non-final**: every Bitcoin Core node
rejects it from the mempool with `non-final`, and no miner will include it.

For contrast, the *closer* side of the same file hard-codes `sent_locktime = 0`
(`closingd/simpleclosed.c:645`) and `handle_closing_sig()` rejects a
`closing_sig` whose `locktime` differs (`simpleclosed.c:506-514`). Only the
closee direction is unguarded.

### Step-by-step exploit

Preconditions: `--experimental-simple-close` on both sides (so `option_simple_close`
is negotiated — see `lightningd/options.c:1499-1501`), and the channel enters
mutual close (either side can start it with `shutdown`).

1. Victim's `channeld` finishes shutdown; `peer_start_simpleclosed()` runs and the
   victim immediately sends its own `closing_complete` with `locktime = 0`
   (`simpleclosed.c:645-651`).
2. Attacker replies `closing_sig` for that proposal. Master stores the victim's
   good tx: `handle_simpleclosed_got_sig()` → `channel_set_last_tx()`
   (`simple_close_control.c:129`). `got_our_sig = true`.
3. Attacker now sends its **own** `closing_complete`, using the same
   `closer_scriptpubkey` it sent in `shutdown` (so `close_tx_check()` passes),
   the same fee, and `locktime = 0xFFFFFFFE` (≈ year 2106 as a timestamp).
4. `handle_closing_complete()` signs that transaction, sends `closing_sig` back
   (line 457), and posts `simpleclosed_closee_broadcast` to master.
5. Master runs `close_tx_check()` — inputs/outputs/scripts all check out, the
   signature verifies — and calls `channel_set_last_tx()`, **overwriting the good
   tx from step 2 and, with it, the last commitment transaction**.
6. `got_peer_complete = true`, the exchange loop exits, `simpleclosed_complete`
   is sent, and `handle_simpleclosed_complete()` calls
   `drop_to_chain(ld, channel, true, NULL)` which broadcasts `channel->last_tx`.
   bitcoind rejects it: `non-final`.
7. The channel is now `CLOSINGD_COMPLETE` with a `last_tx` that can never confirm.
   `resend_closing_transactions()` will keep re-broadcasting the same dead
   transaction after each restart, and any subsequent
   `channel_fail_permanent()` → `drop_to_chain(cooperative=false)` broadcasts the
   *same* `channel->last_tx` (`peer_control.c:480-483`) — the commitment tx is gone.

### Why existing guards do not stop it

Guards I checked and why each fails:

* `close_tx_check()` (`simple_close_control.c:37-91`) — checks input count, that
  the input spends the funding outpoint, and that every output script is one of
  `shutdown_scriptpubkey[LOCAL]`, `shutdown_scriptpubkey[REMOTE]`, or a zero-value
  `OP_RETURN`. It never looks at `wtx->locktime` or at input sequences.
* `check_tx_sig()` in both `simpleclosed.c:270-281` and
  `simple_close_control.c:171` — a signature over a non-final transaction is
  perfectly valid; SIGHASH_ALL commits to the locktime, which is exactly why the
  attacker gets a usable signature.
* `create_simple_close_tx()` ends with `assert(bitcoin_tx_check(tx))` — that only
  checks internal PSBT/tx consistency, not finality.
* `handle_closing_sig()`'s `locktime != sent_locktime` check
  (`simpleclosed.c:506-514`) only guards the *closer* direction.
* `valid_shutdown_scriptpubkey()` (`simpleclosed.c:352-357`) validates scripts, not
  locktime.
* `invalid_last_tx()` in `drop_to_chain()` (`peer_control.c:446`) only detects the
  ancient "no tx stored" sentinel.

### Suggested fix

In `handle_closing_complete()`, reject a `closing_complete` whose `locktime` is
not usable now, before signing. The natural rule (matching what CLN itself sends
and what the anti-fee-sniping rationale implies) is: accept `locktime == 0` or
`locktime <= current_blockheight` for height-encoded values, and reject anything
`>= 500000000` unless it is `<= now`. `simpleclosed` would need the current
blockheight passed in `simpleclosed_init`. Belt-and-braces: add a locktime/finality
check to `close_tx_check()` so master never stores an unbroadcastable tx in
`channel->last_tx`, and consider keeping the commitment tx in a separate column
from the mutual-close tx.

---

## Finding 2 — HIGH: splice accepter accepts an arbitrary peer-chosen `locktime` (marked `DTODO`), and the force-close path then has nothing valid to broadcast

### Location

`channeld/channeld.c:4198-4400` (`splice_accepter()`), specifically 4338-4339;
`lightningd/peer_control.c:468-483` (`drop_to_chain()`).

### The code

```c
/* channeld/channeld.c:4333-4347 */
	check_tx_abort(peer, abort_msg, NULL);

	assert(ictx->pause_when_complete == false);
	peer->splicing->sent_tx_complete = true;

	/* DTODO validate locktime */
	ictx->current_psbt->fallback_locktime = locktime;

	splice_funding_index = find_channel_funding_input(ictx->current_psbt,
							  &peer->channel->funding);
```

`locktime` comes straight from the peer, for both entry points:

```c
/* channeld/channeld.c:4229-4237 (WIRE_SPLICE_INIT) */
		if (!fromwire_splice_init(tmpctx, inmsg,
					  &channel_id,
					  &peer->splicing->opener_relative,
					  &funding_feerate_perkw,
					  &locktime,
					  &peer->splicing->remote_funding_pubkey,
					  &splice_init_tlvs))
/* channeld/channeld.c:4246-4252 (WIRE_TX_INIT_RBF) */
		if (!fromwire_tx_init_rbf(tmpctx, inmsg,
					  &channel_id,
					  &locktime,
					  &funding_feerate_perkw,
					  &init_rbf_tlvs))
```

Everything the accepter *does* check is right next to it, which makes the omission
clear:

```c
/* channeld/channeld.c:4267-4285 */
	if (!is_stfu_active(peer))
		peer_failed_warn(...  "Must be in STFU mode before intiating splice");
	if (!channel_id_eq(&channel_id, &peer->channel_id))
		peer_failed_warn(... "Splice internal error: mismatched channelid");
	if (!pubkey_eq(&peer->splicing->remote_funding_pubkey,
		       &peer->channel->funding_pubkey[REMOTE]))
		status_info("Splice peer is rotating funding pubkey");
	if (funding_feerate_perkw < peer->feerate_min)
		peer_failed_warn(... "Splice feerate_perkw is too low");

	/* TODO: Add plugin hook for user to adjust accepter amount */
	peer->splicing->accepter_relative = 0;
```

There is **no operator/plugin approval** for an incoming splice — CLN auto-ACKs it
(`towire_splice_ack`, line 4288). And `option_splice` / `option_quiesce` are in the
**default** feature set:

```c
/* lightningd/lightningd.c:930-939 */
		OPTIONAL_FEATURE(OPT_QUIESCE),
		...
		OPTIONAL_FEATURE(OPT_ANCHORS_ZERO_FEE_HTLC_TX),
		OPTIONAL_FEATURE(OPT_SPLICE),
```

### Why it is a bug

The splice funding transaction spends the current channel funding output. The
initiator supplies every input in the interactive-tx exchange, including the
`nSequence` of the shared input (`common/interactivetx.c:620-627`, the
`psbt_append_input(..., sequence, ...)` call), and now also the `nLockTime`. An
initiator who picks `nLockTime` far in the future and any `nSequence != 0xFFFFFFFF`
produces a transaction that is permanently non-final: neither party can ever get
it confirmed, but both have signed it and CLN records it as an inflight.

The second half of the problem is that once an inflight exists, the unilateral
close path stops broadcasting the current commitment:

```c
/* lightningd/peer_control.c:466-483 */
		/* We need to drop *every* commitment transaction to chain */
		if (!cooperative && !list_empty(&channel->inflights)) {
			list_for_each(&channel->inflights, inflight, list) {
				if (!inflight->last_tx)
					continue;
				tal_arr_expand(&txs, sign_and_send_last(tmpctx,
									ld,
									channel,
									cmd_id,
									inflight->last_tx,
									&inflight->last_sig));
			}
		} else
			tal_arr_expand(&txs, sign_and_send_last(tmpctx, ld,
								channel, cmd_id,
								channel->last_tx,
								&channel->last_sig));
```

Every `inflight->last_tx` spends the splice output, which will never exist. The
still-valid `channel->last_tx` (the commitment on the *current* funding, kept up
to date by `peer_got_commitsig()` → `channel_set_last_tx()`,
`lightningd/peer_htlcs.c:2168`) is deliberately skipped.

### Step-by-step exploit

1. Attacker connects to the victim (they share a channel; the attacker does not
   need to be the opener).
2. Attacker sends `stfu`. `handle_stfu()` (`channeld.c:300-362`) accepts it
   because `option_quiesce` is on by default, records `stfu_initiator = REMOTE`,
   and the victim replies `stfu`.
3. Attacker sends `splice_init` with `funding_feerate_perkw >= peer->feerate_min`,
   `relative_satoshis` slightly negative (so the fee is paid out of its own
   channel balance and it needs no external UTXO), and
   `locktime = 0xFFFFFFFE`.
4. Victim auto-ACKs (`splice_ack`) with `accepter_relative = 0`.
5. Interactive-tx: attacker adds the shared funding input with
   `nSequence = 0xFFFFFFFD` and one output (the new channel funding output). The
   victim contributes nothing and answers `tx_complete`.
6. Line 4339 stamps `fallback_locktime = 0xFFFFFFFE` onto the PSBT. Balance and
   fee checks in `check_balances()` (3403-3720) all pass — none of them look at
   locktime or sequences. The victim signs, adds the inflight, exchanges
   `commitment_signed`/`tx_signatures`.
7. The splice tx is broadcast by both sides and rejected as `non-final` for the
   next ~80 years.
8. The victim now has a channel with a permanently pending inflight. A subsequent
   `close` that the attacker refuses to cooperate with, or any
   `channel_fail_permanent()`, takes the `!list_empty(&channel->inflights)` branch
   above and publishes only transactions that spend a non-existent outpoint.

### Why existing guards do not stop it

* `check_balances()` (`channeld.c:3403-3720`) validates relative amounts, reserve,
  and that each side pays its share of the fee at `feerate_per_kw`. It never
  inspects `psbt->fallback_locktime` or input sequences. I read all of it.
* `funding_feerate_perkw < peer->feerate_min` (line 4280) is the only feerate
  guard, and a non-final tx's feerate is irrelevant.
* `process_interactivetx_updates()` (`common/interactivetx.c:480-860`) enforces
  serial-id parity, duplicate detection, 252-input/252-output and
  4096-message caps, segwit-ness of prevouts, and standard output scripts. It
  does not constrain sequences or locktime. I read the whole message loop.
* `psbt_finalize()` / `psbt_txid()` do not validate finality.
* `lightningd` side: `handle_add_inflight()` (`channel_control.c:891-948`)
  copies the PSBT into the DB without any locktime check.
* There is no `openchannel2`-style hook for splices — the `TODO: Add plugin hook`
  comment at line 4285 confirms it.

### Confidence

The unvalidated locktime and the missing approval hook are **verified in code**
(the `DTODO` comment is the author's own admission). The downstream consequence —
that `drop_to_chain()` will not publish `channel->last_tx` while a splice inflight
exists — is **verified in code** as quoted, but I could not run the node, so the
exact end-state (whether an operator has any supported recovery path such as an
RBF that the attacker would have to cooperate with) is **inferred**. Even under
the most charitable reading, the channel is wedged in "awaiting splice" until the
attacker chooses to cooperate.

### Suggested fix

Validate `locktime` in `splice_accepter()` exactly as the `DTODO` says: require
`locktime <= current blockheight` for height-encoded values and reject
`>= 500000000` values that are in the future; channeld already tracks
`peer->our_blockheight`. Additionally: (a) constrain the shared input's
`nSequence`, and (b) in `drop_to_chain()`, always include `channel->last_tx`
alongside the inflight commitments when inflights exist, since the current funding
output may still be unspent.

---

## Finding 3 — MEDIUM: `queue_channel_ranges()` out-of-bounds read and infinite message-generating loop

### Location

`connectd/queries.c:641-711` (`queue_channel_ranges()`), reached from
`handle_query_channel_range()` at 715-752; the input array is built by
`gather_range()` at 564-634.

### The code

```c
/* connectd/queries.c:658-682 */
	do {
		size_t n = tal_count(scids) - off;
		u32 this_num_blocks;

		if (n > limit) {
			status_debug("reply_channel_range: splitting %zu-%zu of %zu",
				     off, off + limit, tal_count(scids));
			n = limit;

			/* ... and reduce to a block boundary. */
			while (short_channel_id_blocknum(scids[off + n - 1])
			       == short_channel_id_blocknum(scids[off + limit])) {
				/* We assume one block doesn't have limit #
				 * channels.  If it does, we have to violate
				 * spec and send over multiple blocks. */
				if (n == 0) {
					status_broken("reply_channel_range: "
						      "could not fit %zu scids for %u!",
						      limit,
						      short_channel_id_blocknum(scids[off + n - 1]));
					n = limit;
					break;
				}
				n--;
			}
			/* Get *next* channel, add num blocks */
			this_num_blocks
				= short_channel_id_blocknum(scids[off + n])
				- first_blocknum;
		} else
			/* Last one must end with correct total */
			this_num_blocks = number_of_blocks;
		...
		first_blocknum += this_num_blocks;
		number_of_blocks -= this_num_blocks;
		off += n;
	} while (number_of_blocks);
```

### Why it is a bug

Two defects, both in the `while` loop:

**(a) Off-by-one: the `n == 0` guard is evaluated one iteration too late.** The
loop *condition* dereferences `scids[off + n - 1]` before the body's `if (n == 0)`
runs. Starting from `n = limit` and decrementing, the condition is eventually
evaluated with `n == 0`, reading `scids[off - 1]`. When `off == 0` that is a read
one element *before* the tal array — 8 bytes of the `tal_hdr` preceding the data.
It is inside the same malloc'd block, so it will not segfault or trip ASan, but it
is an out-of-bounds array access whose value then steers control flow.

**(b) The garbage read normally mismatches, so the loop exits with `n == 0`, and
the caller then makes no forward progress.** With `n == 0`:

```
this_num_blocks = blocknum(scids[off + 0]) - first_blocknum
first_blocknum += this_num_blocks;   /* == blocknum(scids[off]) */
number_of_blocks -= this_num_blocks;
off += 0;                            /* no progress */
```

On the very next iteration `n` is unchanged, the same `while` drives `n` to 0
again, and now `this_num_blocks == blocknum(scids[off]) - blocknum(scids[off]) == 0`,
so `first_blocknum`, `number_of_blocks` and `off` are all unchanged forever. Each
iteration calls `send_reply_channel_range()` → `inject_peer_msg()` →
`msg_enqueue(peer->peer_outq, ...)` (`connectd/multiplex.c:102-114`), which is an
unbounded queue. connectd never returns to its event loop: it spins in a tight
loop allocating and enqueuing `reply_channel_range` messages until it is OOM-killed.
connectd is a single process handling *all* peers, so this takes the node's
networking down entirely.

The precondition for reaching `n == 0` is `limit + 1` array entries in the same
block starting at `off`. `max_entries()` (`queries.c:519-561`) gives
`limit = 65490/8 = 8186` with no TLV options and `limit = 65482/24 = 2728` when the
peer sets both `QUERY_ADD_TIMESTAMPS` and `QUERY_ADD_CHECKSUMS` — which it can, in
the same query.

Note also that `gather_range()` no longer produces a sorted array. Its own comment
records the regression:

```c
/* connectd/queries.c:593-596 */
	/* We used to maintain a uintmap of channels by scid, but
	 * we no longer do, making this more expensive.  But still
	 * not too bad, since it's usually in-mem */
	for (size_t i = 0; i < gossmap_max_chan_idx(gossmap); i++) {
```

`gossmap_chan_byidx()` (`common/gossmap.c:219-226`) indexes an allocation array
with a free list, i.e. gossip-store order, not scid order. The block-boundary
logic and the `first_blocknum`/`number_of_blocks` arithmetic below it all assume
ascending block order, so the emitted `reply_channel_range` ranges are also wrong
in general (a separate BOLT #7 conformance bug). Channels announced back-to-back
by one node do land on consecutive indices, which is what makes the attack layout
easy to arrange.

### Step-by-step exploit

1. Attacker publishes one on-chain transaction containing 2 729 P2WSH outputs of
   330 sat each (≈ 0.009 BTC plus fees at today's prices; the outputs are 2-of-2
   of key pairs it owns).
2. It gossips 2 729 `channel_announcement`s (all valid — the funding outputs
   really exist) plus a `channel_update` for each (required, see the
   `gossmap_chan_set()` filter at `queries.c:605`). All 2 729 scids share the same
   block height `B`, and they land on consecutive gossmap indices.
3. It connects to the victim and sends
   `query_channel_range(chain_hash, first_blocknum = B, number_of_blocks = 1,
   query_option_flags = TIMESTAMPS|CHECKSUMS)`.
4. `gather_range()` returns exactly those 2 729 scids; `limit == 2728`; `off == 0`;
   `n == 2729 > limit`.
5. The `while` loop walks `n` from 2728 down to 0 (all entries are in block `B`),
   reads `scids[-1]`, exits, and `this_num_blocks == B - B == 0`.
6. connectd loops forever, memory grows without bound, all peers are lost.

### Why existing guards do not stop it

* The concurrency guard `if (peer->scid_queries || peer->scid_query_nodes)`
  (`queries.c:320-323`) applies to `query_short_channel_ids`, not
  `query_channel_range`; there is no per-peer rate limit on
  `query_channel_range`.
* `handle_query_channel_range()`'s overflow fix-up
  (`queries.c:746-748`) only clamps `first_blocknum + number_of_blocks`.
* The chain_hash mismatch early-return (736-744) does not apply.
* connectd's byte-rate throttle (`multiplex.c:1558-1585`) throttles *reading*; it
  cannot interrupt a synchronous loop that is already running.
* The `if (n == 0)` branch inside the loop *is* the intended handling of this
  case, but it is unreachable in practice: it only fires if the out-of-bounds read
  happens to match `blocknum(scids[off+limit])`, i.e. if 24 bits of tal header
  happen to equal the block height.

### Suggested fix

Hoist the guard above the dereference and make the degenerate case advance:

```c
			while (n > 0
			       && short_channel_id_blocknum(scids[off + n - 1])
				  == short_channel_id_blocknum(scids[off + limit])) {
				n--;
			}
			if (n == 0) {
				status_broken(...);
				n = limit;   /* violate spec, but make progress */
			}
```

and separately, sort the array returned by `gather_range()` by scid (the
downstream block arithmetic requires it).

---

## Finding 4 — MEDIUM: closee signs a `closer_scriptpubkey` that master then refuses, force-closing the channel

### Location

`closingd/simpleclosed.c:352-362` (closer-script validation) and `:457` (the reply
is sent *before* master ever sees the transaction);
`lightningd/simple_close_control.c:49-89` (`close_tx_check()`), `:160-166`
(rejection path).

### The code

The closee validates only the *form* of the peer's script:

```c
/* closingd/simpleclosed.c:346-362 */
	/* BOLT #2:
	 * The receiver of `closing_complete` (aka. "the closee"):
	 * ...
	 * - If `closer_scriptpubkey` is invalid (as detailed in the [`shutdown` requirements]...):
	 *   - SHOULD ignore `closing_complete`.
	 */
	if (!valid_shutdown_scriptpubkey(closer_script, anysegwit, false,
			option_simple_close))
		peer_failed_warn(pps, &their_cid,
			"Invalid closer_scriptpubkey in closing_complete: %s",
			tal_hex(tmpctx, closer_script));
```

Note the asymmetry two dozen lines earlier: the *closee's own* script must match
what it last sent, and the BOLT quote CLN itself embeds says the reference point
is "from `closing_complete` **or** from the initial `shutdown`" — i.e. the spec
explicitly contemplates the script being updated in `closing_complete`:

```c
/* closingd/simpleclosed.c:337-345 */
	 * - If `closee_scriptpubkey` does not match the last script it sent (from `closing_complete` or from the initial `shutdown`):
	 *   - SHOULD ignore `closing_complete`.
	...
	if (!scripteq(closee_script, our_last_script)) {
		peer_failed_warn(pps, &their_cid, ...);
	}
```

Master, however, requires every output to match one of the two *stored shutdown*
scripts:

```c
/* lightningd/simple_close_control.c:57-88 */
		const u8 *script = tal_dup_arr(ctx, u8,
					       out->script, out->script_len, 0);
		if (scripteq(script, channel->shutdown_scriptpubkey[LOCAL]))
			continue;
		if (scripteq(script, channel->shutdown_scriptpubkey[REMOTE]))
			continue;
		/* Our own output is always paid to shutdown_scriptpubkey[LOCAL]
		 * (master passes it to closingd verbatim); we never substitute
		 * an OP_RETURN for it.  So an OP_RETURN output that matches
		 * neither stored script can only be the peer's closer_scriptpubkey.
		 ... */
		if (feature_negotiated(...)
		    && is_valid_op_return(script, tal_bytelen(script))
		    && amount_sat_eq(bitcoin_tx_output_get_amount_sat(tx, i),
				     AMOUNT_SAT(0)))
			continue;
		return tal_fmt(ctx,
			"output %zu goes to unknown script %s",
			i, tal_hex(ctx, script));
```

and rejection is fatal for the channel:

```c
/* lightningd/simple_close_control.c:160-166 */
	const char *err = close_tx_check(tmpctx, channel, tx);
	if (err) {
		channel_internal_error(channel,
			"bad simpleclosed_closee_broadcast: %s",
			err);
		return;
	}
```

`channel_internal_error()` → `channel_fail_permanent()` → `channel_fail_perm()`
→ `drop_to_chain(..., cooperative=false, ...)` (`lightningd/channel.c:1231-1257`,
`1071-1120`).

### Why it is a bug

The daemon and master disagree about what a legal `closer_scriptpubkey` is. A
peer that uses any *different but valid* script in `closing_complete` — which is
one of the motivations for `option_simple_close`, and which the BOLT bullet
quoted in CLN's own source permits — makes the victim:

1. sign that transaction,
2. **send `closing_sig` to the peer** (`simpleclosed.c:457`), handing over a
   complete, broadcastable mutual close, and only then
3. hit `close_tx_check()` failure in master and force-close the channel
   unilaterally.

The order matters: the peer already has what it wanted before the victim's error
handling runs.

### Step-by-step exploit / accidental trigger

1. Channel enters mutual close; the peer sent `shutdown` with script `S1`.
2. Peer sends `closing_complete` with `closer_scriptpubkey = S2` (any valid
   P2WPKH/P2WSH/witness-v1..v16), correct `closee_scriptpubkey`, a fee within its
   balance, `locktime = 0`.
3. `handle_closing_complete()` passes all of its checks, signs, replies
   `closing_sig`, and posts the tx to master.
4. `close_tx_check()` sees `S2 != channel->shutdown_scriptpubkey[REMOTE]` and
   `S2 != channel->shutdown_scriptpubkey[LOCAL]`, and `S2` is not a zero-value
   `OP_RETURN` → error.
5. `channel_internal_error()` → unilateral close: on-chain commitment fees,
   `to_self_delay` CSV lock-up of the victim's balance, loss of the channel.

### Why existing guards do not stop it

* `valid_shutdown_scriptpubkey()` in the daemon deliberately allows any
  well-formed script; it has no notion of "the script they sent in `shutdown`".
* There is no comparison of `closer_script` against
  `peer->remote_upfront_shutdown_script`/`shutdown_scriptpubkey[REMOTE]` anywhere
  in `simpleclosed.c` — I grepped the whole file.
* The `is_valid_op_return` escape hatch in `close_tx_check()` only covers
  zero-valued OP_RETURN outputs, not a normal alternative payout script.
* `channel_internal_error()` does not downgrade to a warning outside developer
  mode — it goes straight to `channel_fail_permanent()`.

### Suggested fix

Pick one contract and enforce it in both places. Either (a) have `simpleclosed`
reject a `closer_scriptpubkey` that differs from `channel->shutdown_scriptpubkey[REMOTE]`
*before* signing and replying — a `peer_failed_warn()` costs only a reconnect — or,
better and spec-conformant, (b) let master accept any output that satisfies
`valid_shutdown_scriptpubkey()` for the closer side, and update
`channel->shutdown_scriptpubkey[REMOTE]` when the peer changes it. In either case,
`close_tx_check()` should never be able to produce a *permanent* channel failure
from a peer message that `simpleclosed` already accepted.

---

## Finding 5 — MEDIUM: splice interactive-tx that omits the shared funding input crashes channeld (repeatable)

### Location

`channeld/channeld.c:1754-1772` (`find_channel_funding_input()`),
`channeld/channeld.c:3217-3245` (`find_channel_output()`),
call sites at `4341-4347`.

### The code

```c
/* channeld/channeld.c:1754-1772 */
static u32 find_channel_funding_input(const struct wally_psbt *psbt,
				      const struct bitcoin_outpoint *funding)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct bitcoin_outpoint psbt_outpoint;
		wally_psbt_input_get_outpoint(&psbt->inputs[i], &psbt_outpoint);

		if (!bitcoin_outpoint_eq(&psbt_outpoint, funding))
			continue;

		if (funding->n == psbt->inputs[i].index)
			return i;
	}

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Unable to find splice funding tx");

	return UINT_MAX;
}
```

`find_channel_output()` is the same shape (`status_failed(STATUS_FAIL_INTERNAL_ERROR,
"Unable to find channel output")` at 3242-3243).

### Why it is a bug

`status_failed()` is a fatal, non-recoverable exit of the subdaemon. Both
functions are called on a PSBT that the *peer* fully controls: as the splice
accepter, `ictx->desired_psbt = NULL` (`channeld.c:4320`), so CLN contributes
nothing and the initiator decides the entire transaction. Nothing in
`process_interactivetx_updates()` requires the shared funding input to be added —
I read the whole message loop in `common/interactivetx.c:480-860`; the checks are
serial-id parity, duplicates, prevout segwit-ness, standard scripts, the 252/4096
caps, and nothing else. `tx_complete` from both sides ends the negotiation
regardless of what the transaction contains.

The peer therefore reaches line 4341 with a PSBT that does not spend the funding
outpoint (or, for `find_channel_output()`, does not contain the new 2-of-2 output),
and channeld dies.

### Step-by-step exploit

1. Attacker sends `stfu`; victim quiesces (default features).
2. Attacker sends `splice_init` with an acceptable `funding_feerate_perkw`.
3. Victim sends `splice_ack` and enters `process_interactivetx_updates()`.
4. Attacker sends a single `tx_add_input` for an unrelated segwit UTXO of its own
   (or nothing at all) followed by `tx_complete`.
5. Victim answers `tx_complete` (it has nothing to add).
6. `find_channel_funding_input(ictx->current_psbt, &peer->channel->funding)` finds
   no match → `status_failed(STATUS_FAIL_INTERNAL_ERROR, "Unable to find splice funding tx")`.
7. channeld exits. In `lightningd/subd.c:388-421` this is logged via
   `log_broken()`; the subd's death then reaches `channel_errmsg()` with
   `peer_fd == NULL`, which takes the `channel_fail_transient()` path
   (`lightningd/peer_control.c:609-615`). The channel reconnects, and the attacker
   repeats from step 1.

The channel is never force-closed, but it is never usable either, and every cycle
writes a BROKEN entry to the log.

### Why existing guards do not stop it

* `is_stfu_active()` (line 4267) is satisfied — the attacker initiated stfu.
* `check_balances()` and the feerate checks run *after* line 4341, so they never
  get a chance.
* `check_tx_abort()` (line 4333) handles `tx_abort`, not a malformed-but-complete
  negotiation.
* `interactivetx`'s `ictx->shared_outpoint` is only consulted inside the
  `tx_add_input` handler when the peer volunteers `tlvs->shared_input_txid`
  (`common/interactivetx.c:539-561`); there is no post-condition check.

### Suggested fix

Make both functions return a failure indication instead of calling
`status_failed()`, and have `splice_accepter()`/`splice_initiator_user_finalized()`
respond with `splice_abort()`/`peer_failed_warn()` when the negotiated transaction
does not contain the shared funding input and the new channel output. A cheap
alternative is to add an explicit post-condition after
`process_interactivetx_updates()`:
`if (!psbt_has_input(ictx->current_psbt, &peer->channel->funding)) splice_abort(...)`.

---

## Finding 6 — LOW: `start_batch` lets a peer make channeld buffer an unbounded number of messages

### Location

`channeld/channeld.c:2480-2503` (`handle_peer_start_batch()`),
`channeld/channeld.c:2410-2445` (`handle_peer_commit_sig_batch()`).

### The code

```c
/* channeld/channeld.c:2418-2440 */
	/* BOLT-f9fd539db6cc6f3e532fdc8cc1ebe8eb1a8fd717
	 *  - If there are pending splice transactions and the sending node did not
	 *    send `start_batch` followed by a batch of `commitment_signed` messages:
	 *    - MUST send an `error` and fail the channel.
	 */
	if (batch_size < 2 && last_inflight(peer))
		peer_failed_err(peer->pps, &peer->channel_id, "Must send a"
				" commitment batch (ie. start_batch) when I"
				" have pending splices inflight.");

	msg_batch = tal_arr(tmpctx, const u8*, batch_size);
	msg_batch[0] = msg;

	/* Already received commitment signed once, so start at i = 1 */
	for (u16 i = 1; i < batch_size; i++) {
		...
		u8 *sub_msg = peer_read(tmpctx, peer->pps);
		...
		msg_batch[i] = sub_msg;
	}
```

### Why it is a bug

`batch_size` is a `u16` straight off the wire with only a *lower* bound check.
There is no upper bound, and no check against
`tal_count(peer->splice_state->inflights) + 1`, which is the only value that can
ever be meaningful (the check at 2288-2294 that `tal_count(msg_batch) - 1` is
large enough is a *minimum*, not a maximum). A peer sets `batch_size = 65535`,
then feeds 65 534 `commitment_signed` messages of up to 65 535 bytes each. All of
them are allocated on `tmpctx`, which is not cleaned until the outer loop
iteration finishes — roughly 4 GB of resident memory in channeld before a single
signature is checked.

### Why existing guards do not stop it

* connectd's byte-rate throttle (`multiplex.c:1558-1585`) limits bytes per second
  from the peer but does not bound total buffered bytes in the subdaemon.
* The per-message `fromwire_commitment_signed()` and `sub_cs_tlv->funding_txid`
  checks reject malformed messages, but a well-formed `commitment_signed` with a
  bogus `funding_txid` is accepted into `msg_batch` and merely sorted to the back
  by `commit_cmp()`.

### Impact and severity

channeld is per-channel; OOM there costs a reconnect, not the node. Rated LOW
because I could not show node-wide impact — but note the attacker can open the
same situation on every channel it has with the victim simultaneously.

### Suggested fix

```c
	if (batch_size > tal_count(peer->splice_state->inflights) + 1)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "start_batch size %u too large (max %zu)",
				 batch_size,
				 tal_count(peer->splice_state->inflights) + 1);
```

---

## Finding 7 — LOW: `1000000 + fee_proportional_millionths` is still computed in 32 bits in `common/amount.c` (incomplete counterpart to `96f026ecc`)

### Location

`common/amount.c:656-684` (`amount_msat_sub_fee()`), `608-620`
(`amount_msat_mul_div()`).

### The code

Commit `96f026ecc` fixed exactly this expression in `common/onion_decode.c`:

```c
/* common/onion_decode.c:121-122 — the FIXED version */
	p->amt_to_forward = amount_msat(ceil_div((amt - enc->payment_relay->fee_base_msat) * 1000000,
						 (u64)1000000 + enc->payment_relay->fee_proportional_millionths));
```

The identical expression in `common/amount.c` was not fixed:

```c
/* common/amount.c:656-684 */
struct amount_msat amount_msat_sub_fee(struct amount_msat in,
				       u32 fee_base_msat,
				       u32 fee_proportional_millionths)
{
	struct amount_msat out, out_plus_one;
	...
	if (!amount_msat_sub(&out, in, amount_msat(fee_base_msat)))
		return AMOUNT_MSAT(0);
	if (!amount_msat_mul_div(&out, out, 1000000,
				 1000000 + fee_proportional_millionths))
		return AMOUNT_MSAT(0);

	/* If we calc reverse, it must work! */
	assert(within_fee(in, out, fee_base_msat, fee_proportional_millionths));
```

`1000000` is an `int` and `fee_proportional_millionths` is a `u32`; the usual
arithmetic conversions make this a 32-bit unsigned addition. For
`fee_proportional_millionths == 4293967296` (`0xFFF0BDC0`) the sum wraps to
exactly **0**. `amount_msat_mul_div()` then does:

```c
/* common/amount.c:608-620 */
static bool amount_msat_mul_div(struct amount_msat *res,
				struct amount_msat msat, u64 mul, u64 div)
{
	...
	if (mul_overflows_u64(mul, div))
		return false;
	u64 x = msat.millisatoshis;
	res->millisatoshis = mul * (x / div) + (mul * (x % div)) / div;
	return true;
}
```

`mul_overflows_u64(1000000, 0)` is false, so the guard passes and `x / div` is a
**division by zero — SIGFPE**.

A second, independent defect in the same helper: the overflow guard only proves
that the *intermediate* `mul * div` does not overflow; the *result*
`mul * (x/div) + (mul * (x%div))/div` can still wrap silently whenever `mul > div`.
`amount_msat_fee()` calls it with `mul = fee_proportional_millionths` and
`div = 1000000`, so a proportional fee above 10^6 ppm on a large amount returns a
wrapped value while reporting success. `amount_msat_sub_fee()`'s
`assert(within_fee(...))` at line 677 would then abort.

### Reachability — honest assessment

`fee_proportional_millionths` is an unbounded `u32` in `channel_update`, so a
remote peer can put `0xFFF0BDC0` into any node's gossmap. The reachable callers of
`amount_msat_sub_fee()` are all in the routing plugins —
`plugins/askrene/child/refine.c:206,251`, `plugins/askrene/child/child.c:129` —
where `hc->proportional_fee` comes from gossip. So it is remotely *influenced*.
However, a channel advertising a 429 400% proportional fee is astronomically
expensive and the min-cost-flow solver would not normally place it in a candidate
flow, so I could **not** demonstrate a reachable crash. I am reporting it as LOW
on the strength of it being the same bug class that was just fixed after an
external security report, not on a demonstrated exploit.

I checked and ruled out the HTLC-forwarding path: `check_fwd_amount()`
(`lightningd/peer_htlcs.c:334-359`) uses `amount_msat_fee()` with **our own**
configured `next->feerate_base`/`feerate_ppm`, not the peer's, and the fixed
`onion_decode.c:121-122` is the only place a peer-supplied ppm enters the
forwarding math.

### Suggested fix

```c
	if (!amount_msat_mul_div(&out, out, 1000000,
				 (u64)1000000 + fee_proportional_millionths))
```

and give `amount_msat_mul_div()` a real result-overflow check (or an explicit
`div == 0` guard). `tests/fuzz/fuzz-amount-arith.c` already exercises
`amount_msat_sub_fee()` with arbitrary `fee_prop` at line 201 — worth checking why
this was not caught.

---

## Finding 8 — LOW: `channel_update_funding()`'s negative-balance guards are dead code

### Location

`common/initial_channel.c:156-182`.

### The code

```c
/* common/initial_channel.c:156-182 */
const char *channel_update_funding(struct channel *channel,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   s64 splice_amnt)
{
	s64 funding_diff = (s64)funding_sats.satoshis - (s64)channel->funding_sats.satoshis; /* Raw: splicing */
	s64 remote_splice_amnt = funding_diff - splice_amnt;

	channel->funding = *funding;
	channel->funding_sats = funding_sats;

	if (splice_amnt * 1000 + channel->view[LOCAL].owed[LOCAL].millisatoshis < 0) /* Raw: splicing */
		return tal_fmt(tmpctx, "Channel funding update would make local"
			       " balance negative.");

	channel->view[LOCAL].owed[LOCAL].millisatoshis += splice_amnt * 1000; /* Raw: splicing */
	channel->view[REMOTE].owed[LOCAL].millisatoshis += splice_amnt * 1000; /* Raw: splicing */

	if (remote_splice_amnt * 1000 + channel->view[LOCAL].owed[REMOTE].millisatoshis < 0) /* Raw: splicing */
		return tal_fmt(tmpctx, "Channel funding update would make"
			       " remote balance negative.");
	...
```

### Why it is a bug

`millisatoshis` is a `u64` (`common/amount.h`, `struct amount_msat`). In
`s64_expr + u64_expr` the signed operand is converted to `unsigned long`, so the
whole expression has type `u64` and `< 0` is **always false**. Both guards are
no-ops; the compiler's `-Wtype-limits` would say so, but that is not in `-Wall`
and CLN's default `CWARNFLAGS` (see `configure:54, 600`) do not enable it.

If a negative `splice_amnt` larger than the balance ever reached this function,
`owed[LOCAL].millisatoshis` would wrap to ~2^64 and the very next commitment build
would hit `to_balance()`'s `assert(balance->msat >= 0)`
(`channeld/full_channel.c:28-32`) or `commit_tx()`'s
`assert(!amount_msat_greater_sat(total_pay, funding_sats))`
(`channeld/commit_tx.c:151-153`) — an abort, not a silent balance corruption.

### Why I am not rating it higher

The value reaching this function is `inflight->splice_amnt`, which was validated
during negotiation by `check_balances()`'s
`amount_msat_can_add_sat_s64(in[TX_INITIATOR/ACCEPTER], ...)` checks
(`channeld/channeld.c:3448-3465`) and by
`amount_msat_add_sat_s64()` at 3510-3536. I could not find a path that reaches
`channel_update_funding()` with an over-large negative amount, so this is a
disabled safety net rather than a live bug. It is worth fixing because it is the
last line of defence in exactly the area (splice arithmetic) where the rest of
this report found real problems.

### Suggested fix

```c
	if (!amount_msat_can_add_sat_s64(channel->view[LOCAL].owed[LOCAL], splice_amnt))
		return tal_fmt(tmpctx, "Channel funding update would make local"
			       " balance negative.");
```
(`amount_msat_can_add_sat_s64()` already exists, `common/amount.c:421-426`, and is
used correctly elsewhere in `check_balances()`.)

---

## Finding 9 — LOW: `update_view_from_inflights()` tests one array slot and writes another

### Location

`channeld/channeld.c:3723-3746`.

### The code

```c
/* channeld/channeld.c:3723-3746 */
static void update_view_from_inflights(struct peer *peer)
{
	struct inflight **inflights = peer->splice_state->inflights;

	for (size_t i = 0; i < tal_count(inflights); i++) {
		s64 splice_amnt = inflights[i]->amnt.satoshis; /* Raw: splicing */
		s64 funding_diff = sats_diff(inflights[i]->amnt, peer->channel->funding_sats);
		s64 remote_splice_amnt = funding_diff - inflights[i]->splice_amnt;

		if (splice_amnt < peer->channel->view[LOCAL].lowest_splice_amnt[LOCAL])
			peer->channel->view[LOCAL].lowest_splice_amnt[LOCAL] = splice_amnt;

		if (splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE])
			peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL] = splice_amnt;

		if (remote_splice_amnt < peer->channel->view[LOCAL].lowest_splice_amnt[REMOTE])
			peer->channel->view[LOCAL].lowest_splice_amnt[REMOTE] = remote_splice_amnt;

		if (remote_splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL])
			peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE] = remote_splice_amnt;
	}
}
```

### Why it is a bug

The 1st and 3rd statements are consistent (test slot X, assign slot X). The 2nd
and 4th test the *other* side's slot and assign their own. The obvious intent —
mirroring the first and third — is
`view[REMOTE].lowest_splice_amnt[LOCAL]` guarded by
`view[REMOTE].lowest_splice_amnt[LOCAL]`, and likewise for `[REMOTE]`.

Consequences, with the reset to zero at `channeld.c:459-462` as the starting point:

* With one inflight, statement 2 sets `view[REMOTE].lowest_splice_amnt[LOCAL]`
  correctly, but it has then poisoned the *condition* of statement 4, which will
  skip its assignment whenever `remote_splice_amnt > splice_amnt` — leaving
  `view[REMOTE].lowest_splice_amnt[REMOTE]` at 0, i.e. the peer's splice-out
  amount unreserved in the remote view.
* With more than one inflight (splice RBF), statement 2's condition is compared
  against a slot that never gets updated, so the "minimum" it computes is simply
  the *last* value seen, not the minimum. A later, smaller splice-out can
  overwrite an earlier, larger one.

Those slots feed `get_room_above_reserve()`:

```c
/* channeld/full_channel.c:428-440 */
	/* `lowest_splice_amnt` will always be negative or 0 */
	if (amount_msat_less_eq_sat(owed, amount_sat(-view->lowest_splice_amnt[side]))) {
		status_debug("Relative splice balance invalid");
		return false;
	}
	if (!amount_msat_sub_sat(&owed, owed,
				 amount_sat(-view->lowest_splice_amnt[side]))) {
```

### Why I am not rating it higher

I traced the two call patterns in `add_htlc()` (`full_channel.c:772-880`):

* For an HTLC the **peer** sends, `view = &channel->view[recipient] = view[LOCAL]`
  and `side = sender = REMOTE`, so the slot used is
  `view[LOCAL].lowest_splice_amnt[REMOTE]` — set by statement 3, which is correct.
  The peer therefore cannot use this to double-spend funds it has committed to
  splicing out.
* The corrupted slots are only read when *we* add an HTLC
  (`sender == LOCAL`), so the damage is self-inflicted: we might send an HTLC the
  peer rightly rejects, or leave ourselves short for a splice we committed to.

So: a real correctness defect with no peer-exploitable fund loss that I could
construct. Reported at LOW with that caveat.

### Suggested fix

```c
		if (splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL])
			peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL] = splice_amnt;
		...
		if (remote_splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE])
			peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE] = remote_splice_amnt;
```

---

## Additional observations (informational, no security impact claimed)

* **`connectd/websocketd.c:281-297`** — `websocket_to_lightningd()` restarts the
  XOR mask index at 0 for every `read()`, so a websocket frame that arrives split
  across reads is unmasked incorrectly from the second chunk onwards
  (`apply_mask(buf, rlen, inmask)` uses `i % 4` with `i` reset each time). The
  corrupted bytes go to lightningd, fail BOLT#8 decryption, and the connection
  drops. Correctness/interop, self-inflicted by the peer.
* **`connectd/websocketd.c:270-280`** — `if (mask_set) { memcpy(inmask, frame_hdr
  + hdrsize - 4, 4); hdrsize += 4; }` double-counts the 4 mask bytes. `hdrsize` is
  dead after this point, so it is harmless today, but it is a trap for the next
  editor.
* **`lightningd/channel_control.c:1313`** — `peer_got_shutdown()` calls
  `valid_shutdown_scriptpubkey(scriptpubkey, anysegwit, !anchors, /*option_simple_close=*/false)`.
  With `option_simple_close` negotiated, a spec-compliant peer may send an
  `OP_RETURN` `shutdown` script; CLN warns and `channel_fail_transient()`s. Purely
  an interop bug (transient, not a force-close), but it is the same
  daemon/master inconsistency family as Finding 4.
* **`closingd/simpleclosed.c:415-437`** — in the closee path, `make_close_tx()` is
  passed `local_wallet_index`/`local_wallet_ext_key` together with
  `closer_script` (the *peer's* output), so `psbt_add_keypath_to_last_output()`
  (`common/psbt_keypath.c:37-49`) stamps our BIP32 derivation onto the peer's
  output, while our own (closee) output gets no keypath at all. I checked
  `sign_and_send_last()` → `wallet_extract_owned_outputs()`
  (`lightningd/peer_control.c:319-322`): output ownership is decided by
  scriptpubkey lookup, not by PSBT keypaths, so no phantom UTXO results. Cosmetic,
  but misleading.
* **`channeld/channeld.c:3432-3437`** — `if (htlc_owner(htlc) == opener ? LOCAL :
  REMOTE)` parses as `(htlc_owner(htlc) == opener) ? LOCAL : REMOTE` and then uses
  `LOCAL`(0)/`REMOTE`(1) as a truth value. I worked through all four
  (`our_role`, `htlc_owner`) combinations: the double inversion happens to produce
  exactly the intended mapping, so this is *not* a bug — but it is one keystroke
  away from being one and should get its parentheses.
* **`channeld/commit_tx.c:195`** — `try_subtract_fee()`'s return value is
  discarded, silently zeroing the opener's output if it cannot afford the fee.
  Only the opener loses, and `handle_peer_commit_sig()`'s
  `assert(can_opener_afford_feerate(...))` (channeld.c:2105-2111) fires first, so
  no impact — but that assert is itself a peer-influenced abort and deserves a
  `peer_failed_warn()` instead.

---

## Areas audited and found sound

These are areas I actually read line-by-line and could not break. Listing them so
the negative results are auditable.

* **`common/sphinx.c` — onion parsing/processing.** Checked
  `parse_onionpacket()` (196-229) and `process_onionpacket()` (646-736) for
  bounds. `fromwire_tal_arrn()` (`wire/fromwire.c:239-254`) rejects
  `num > *max`, so the `max - HMAC_SIZE` underflow at `sphinx.c:219` fails safely.
  In `process_onionpacket()`, `paddedheader` is `2 * len(routinginfo)` while
  `max` is only `len(routinginfo)`, so `shift_size <= len(routinginfo)` and the
  `tal_dup_arr(paddedheader + shift_size, len(routinginfo))` at 759-762 lands
  exactly at the end of the buffer — in-bounds. Also checked the
  `payload_size < 2` / `!cursor` guard and the short-onion case (`routinginfo ==
  NULL`) reached via `common/onion_message_parse.c:104`, which is variable-length:
  it fails cleanly.
* **`common/onion_decode.c`.** Verified that `96f026ecc`'s fix is correct for the
  divide-by-zero. Traced the remaining wrapping arithmetic (`amt - fee_base_msat`,
  `cltv_expiry - cltv_expiry_delta` at 121-123) and confirmed that garbage results
  are caught downstream by `check_fwd_amount()`/`check_cltv()` using *our own*
  policy (`lightningd/peer_htlcs.c:334-382, 856-895`), so an attacker cannot
  make us forward more or with a shorter CLTV than our policy allows.
* **`lightningd/peer_htlcs.c` forwarding and final-hop checks.** Read
  `check_fwd_amount()`, `check_cltv()`, `forward_htlc()` (808-945) and
  `handle_localpay()` (435-548). Fee is computed from `next->feerate_base` /
  `next->feerate_ppm`; `htlc_maximum_msat`/`htlc_minimum_msat`,
  `cltv_expiry_delta`, `expiry_too_soon`, `expiry_too_far` and the
  `old_feerate_timeout` grace window are all applied against local config.
* **`lightningd/htlc_set.c` (MPP).** Read all of it. `total_msat` consistency
  (213-223), `amount_msat_accumulate()` overflow check (225-235), the mandatory
  `payment_secret` for multi-part sets (197-202 and 263-266), and the 70-second
  timeout with destructor-based cleanup (29-42, 56-59). No probing or
  over-claiming path found.
* **`common/cryptomsg.c` (BOLT#8 framing) and `connectd/multiplex.c` read path.**
  `cryptomsg_decrypt_body()` rejects `inlen < 16`; the header path reads exactly
  18 bytes and resizes to `len + CRYPTOMSG_BODY_OVERHEAD` (`multiplex.c:1541-1553`).
  Key rotation at n==1000 matches the spec. The per-second byte throttle
  (`multiplex.c:1558-1585`) and the `io_wait` back-pressure on the subd queue
  (1531-1535) mean a peer cannot flood the subd queues.
* **`connectd/queries.c` short-channel-id query path** (as distinct from Finding 3):
  the "no concurrent query" guard at 320-323 fires *before* the scids are decoded,
  and the flags/scids length equality check at 341-352 prevents the
  `peer->scid_query_flags[i]` indexing in `maybe_create_query_responses()`
  (138-182) from running off the end. `common/decode_array.c` is bounded by the
  65 535-byte message size and rejects trailing partial elements.
* **`channeld/full_channel.c` `add_htlc()` (609-937).** Checked in detail: zero
  amount, `htlc_minimum_msat`, `max_accepted_htlcs` (both directions),
  `max_htlc_value_in_flight_msat`, `get_room_above_reserve()` against the
  *sender's* reserve in the *recipient's* view, the anchor 660-sat deduction, the
  opener-affordability check, `local_opener_has_fee_headroom()`, and the
  `max_dust_htlc_exposure_msat` checks at the accelerated
  `htlc_trim_feerate_ceiling()`. The `sum_offered_msatoshis()` /
  `amount_msat_add` / `amount_msat_sub` chain (825-838) checks every return value.
  I could not find an asymmetry a peer can use: the checks that are gated on
  `sender == LOCAL` (the `chainparams->max_payment` cap at 320-325 and the extra
  opener-fee headroom at 843-880) are all *extra* self-restrictions, not omitted
  peer validation.
* **`channeld/commit_tx.c` / `common/initial_commit_tx.c` / `common/htlc_trim.c`.**
  Verified trimming matches BOLT#3 (`htlc_is_trimmed()` uses the
  transaction-owner's dust limit and the right timeout/success fee), the 660-sat
  anchor deduction from the funder, the `to_local`/`to_remote` dust rules, anchor
  output presence rules, BIP69+CLTV output permutation, and the locktime/sequence
  obscured-commitment-number encoding.
* **`closingd/closingd.c` (legacy `closing_signed`).** Read `close_tx()` (55-113),
  `receive_offer()` (225-370), `init_feerange()`/`adjust_feerange()` (373-440),
  `get_overlap()`/`amount_in_range()` (441-466), `adjust_offer()` (468-535) and
  `calc_fee_bounds()` (581-650). The fee is always subtracted from the *opener's*
  output (`amount_sat_sub(&out_minus_fee[opener], out[opener], fee)`, failing
  loudly if unaffordable), `create_close_tx()` asserts
  `total_out <= funding_sats`, our own output is always `out[LOCAL]`, the peer's
  offer must be `>= min_fee_to_accept` before master sees it, and locktime is
  hard-coded to 0. `*maxfee = funding` when `opener == REMOTE` is safe precisely
  because they are the one paying.
* **`closingd/simpleclosed.c` amount handling** (as distinct from Findings 1 and 4).
  `closee_amount` is always our own `local_sat` from
  `simpleclosed_init` (`lightningd/simple_close_control.c:349`), never anything the
  peer supplies; `our_output_dust` uses `channel->our_config.dust_limit`
  (`simple_close_control.c:351`), i.e. *our* dust limit, not the peer's; the
  `fee_satoshis > closer's balance` check at `simpleclosed.c:369-376` is present;
  `check_their_sig()` runs before `peer_write()` in every branch. As closer,
  `handle_closing_sig()` re-checks scripts/fee/locktime against what we sent, and
  requires exactly one signature TLV drawn from the set we offered (506-542).
* **`channeld/channeld.c` reestablish (`peer_reconnect`, 5650-6225).** The
  `next_commitment_number == 0` check added by `eafdd9386` is correctly hoisted
  and complete for the path it guards; `next_revocation_number` handling
  distinguishes retransmit / behind / ahead correctly and routes "ahead" to
  `check_future_dataloss_fields()`. I specifically chased
  `assert(local_next_funding || inflight->remote_tx_sigs)` at line 5911 and
  established it cannot fire: `local_next_funding` is NULL only when
  `inflight->last_tx && inflight->remote_tx_sigs` (condition at 5687), and the
  `missing_user_signatures()` branch sets `inflight = NULL` before the assert is
  reachable.
* **`channeld/channeld.c` HTLC removal handlers.** `handle_peer_fulfill_htlc()`,
  `handle_peer_fail_htlc()`, `handle_peer_fail_malformed_htlc()` (2656-2784) all
  route every non-`REMOVE_OK` result to `peer_failed_warn()`. I noted that
  `channel_fulfill_htlc()` (`full_channel.c:975-1040`) sets `htlc->r` *before* the
  committed/irrevocable state checks, but since every failure path tears down
  channeld, the mutated state is never used — no double-count.
* **`openingd/common.c check_config_bounds()` and `openingd/openingd.c`
  fundee path.** Verified `to_self_delay`, combined reserve vs funding (with the
  660-sat anchor add), `max_htlc_value_in_flight` capping capacity,
  `htlc_minimum_msat`, `max_accepted_htlcs` in `[1, 483]`, feerate min/max, and
  the interaction that defeats a hostile `dust_limit_satoshis`:
  `set_reserve(state, state->remoteconf.dust_limit)` (openingd.c:973) raises *our*
  reserve to at least their dust limit, after which `check_config_bounds()`'s
  `amount_sat_sub(&capacity, funding, reserve)` fails for any large value. The
  `allowdustreserve` "all-dust commitment" corner case is explicitly handled at
  openingd.c:456-480. `4b34ad332`'s `max_channel_funding()` is applied at every
  dualopend entry point (2495, 2628, 3262, 3578, 3769) and at openingd.c:928.
* **`common/interactivetx.c` message loop (480-860).** serial-id parity,
  duplicate serial-ids, duplicate outpoints, `prevtx_out` in range,
  segwit-only prevouts, `is_known_scripttype()` outputs, 252 input / 252 output
  caps, 4096-message caps, and removal restricted to the adding side — all
  present and correct. (Its gap, the absent shared-input post-condition, is
  Finding 5.)
* **`common/shutdown_scriptpubkey.c`.** `is_valid_op_return()` and
  `is_valid_witnessprog()` bounds are correct, including the zero-length input
  case (`fromwire_u8()` NULLs the cursor and subsequent pulls return 0).
* **`connectd/websocketd.c` HTTP handshake** (the `f0c702ed8` change).
  `get_http_hdr()` is only entered after `http_headers_complete()` has confirmed a
  `\r\n\r\n`, and the loop terminates at the blank line (`hdrlen == 0`) before it
  can walk past the header block into buffered frame data, so the unchecked
  `memmem()` return cannot be NULL in practice. `hdrlen > hdrnamelen` was added
  alongside `strncasecmp()`, which correctly prevents the `buf[hdrnamelen]` read
  from going past the line. `read_payload_header()`'s `frame_hdr[20]` is large
  enough for the 14-byte worst case.
* **`lightningd/peer_control.c handle_peer_spoke()`** (2010-2140): unknown
  channel-ids get an error rather than an unbounded subdaemon spawn, and
  `peer->uncommitted_channel` limits simultaneous opens to one.
* **`common/channel_type.c` / `common/features.c`**: `channel_type_accept()`
  whitelists variant bits rather than accepting arbitrary feature vectors.

---

## Uncertain / needs dynamic testing

Things I suspect but could not settle from the source alone. None of these are
counted in the summary table.

1. **Finding 2's end-state.** I verified that `drop_to_chain()` skips
   `channel->last_tx` whenever `channel->inflights` is non-empty and
   `cooperative == false`. What I could not verify statically is whether an
   operator has *any* supported recovery once a splice funding tx is permanently
   non-final — e.g. whether `splice` RBF (`tx_init_rbf`) can be driven from our
   side without the attacker's cooperation, or whether `channel->last_tx` can be
   coaxed out some other way. A regtest with `nLockTime = 0xFFFFFFFE` on the
   splice and then a `close --force` would settle it in minutes.
2. **Finding 1 under restart.** I did not check whether restarting lightningd, or
   a reconnect while in `CLOSINGD_COMPLETE`, restarts `simpleclosed` and gives the
   victim a chance to propose a `locktime = 0` transaction that the attacker might
   sign. If it does, the severity drops from "permanent" to "stuck until the
   attacker relents", which is still bad but not fatal.
3. **Finding 3's economics.** My cost estimate (2 729 P2WSH dust outputs in one
   block) assumes gossipd will accept and store all of them and that they end up on
   consecutive `gossmap` indices. Both are plausible from the code but worth
   confirming with a regtest that stuffs a block and then issues the crafted
   `query_channel_range`. Also worth checking whether any *historical* mainnet
   block already has ≥ 2 729 announced channels, which would make the bug
   triggerable today by any peer with a one-line query.
4. **`assert(can_opener_afford_feerate(...))` in `handle_peer_commit_sig()`
   (`channeld/channeld.c:2105-2111`).** I compared the fee/dust/view inputs used
   by `channel_update_feerate()` at `update_fee` time against those used at
   `commitment_signed` time and they appear consistent, so I did not report it.
   But it is an `assert()` on a condition that depends on peer-chosen feerates and
   peer-chosen HTLC timing, in a code path with `fee_states` staging in between
   (`common/fee_states.c`). A fuzzer that interleaves `update_fee`,
   `update_add_htlc` and `commitment_signed` around the affordability boundary is
   the right tool.
5. **`htlc_trim_feerate_ceiling()` (`common/htlc_trim.c:56-64`)** computes
   `feerate + feerate/4` in `u32`, which overflows above ~3.44e9. I convinced
   myself the feerate cannot climb that high — `feerate_same_or_better()`
   (`channeld/channeld.c:695-707`) only lets a peer *exceed* `feerate_max` by
   going *downwards* from the current value, and openingd rejects an out-of-range
   opening feerate — but `f2a0fb2c5`'s commit message asserts the opposite
   ("current_feerate is chosen by the peer in open_channel or update_fee, they
   could choose an absurdly high value"), so one of us is wrong and it is worth a
   fuzz run.
6. **`onchaind/`.** I scoped this out deliberately: onchaind reacts to on-chain
   transactions, so `--offline` does not make a node immune to anything it does,
   which puts it outside this audit's definition of the P2P surface. It is *not*
   covered by this report and should be audited separately.
7. **`common/amount.c amount_msat_mul_div()` result overflow** (Finding 7's second
   half). I did not enumerate every caller. `plugins/` uses it heavily with
   gossip-derived `fee_proportional_millionths`, and
   `tests/fuzz/fuzz-amount-arith.c` already has the harness — extending it to
   assert on result-overflow rather than just on the boolean return would be a
   cheap win.
