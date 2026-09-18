# Core Lightning P2P fund-loss audit

**Tree:** `v26.06-273-gc1551c557` (`c1551c557`)
**Date:** 2026-09-01
**Scope:** Peer-to-peer money movement (`connectd`, `channeld`, `openingd`, `closingd`, `hsmd` splice signing, HTLC/onion decode). RPC-only, gossip-only, and plugin bugs are out of scope unless they are the last check on a P2P path.
**Mitigation under test:** `--offline` (do not listen, do not reconnect). Every issue below requires a live peer connection unless a previously signed transaction is already in the mempool.

This is a source audit, not a live exploit run. Findings are ordered by expected impact on operator funds.

Splicing (`OPT_SPLICE`) and large channels (`OPT_LARGE_CHANNELS` / wumbo) are **on by default**. Incoming `splice_init` is auto-acked with `accepter_relative = 0` (no plugin hook). `max_htlc_value_in_flight` defaults to `UINT64_MAX`.

---

## Finding 1 — CRITICAL: `tx_abort` after we signed a splice drops tracking; peer broadcasts

**Loss of funds:** yes (channel capacity stuck in a 2-of-2 we can no longer spend)
**Requires P2P:** yes. `--offline` prevents new splices. Does not help if we already signed and then aborted while online.
**Confidence:** high on the bug; high that the on-chain result is unrecoverable without peer cooperation or a pre-abort wallet backup.

### Root cause

`check_tx_abort` is supposed to refuse `tx_abort` after we have signed the splice. It looks up the inflight by txid, then calls `have_i_signed_inflight` **on the pointer that is still `NULL`**, and only then assigns the match:

```1882:1895:channeld/channeld.c
	inflight = NULL;
	for (size_t i = 0; txid && i < tal_count(peer->splice_state->inflights); i++) {
		struct inflight *itr = peer->splice_state->inflights[i];
		if (!bitcoin_txid_eq(&itr->outpoint.txid, txid))
			continue;
		if (have_i_signed_inflight(peer, inflight)) {  /* inflight is NULL here */
			peer_failed_err(...);
		}
		inflight = itr;  /* assigned only after the check */
	}
```

`have_i_signed_inflight(peer, NULL)` returns false immediately (`channeld.c:1781-1782`). The guard never fires.

Master then deletes the inflight (PSBT, their/our splice commitment `last_tx`, scriptpubkey watch) and restarts `channeld`:

```346:362:lightningd/channel_control.c
	if (outpoint) {
		inflight = list_tail(&channel->inflights, ...);
		if (!bitcoin_outpoint_eq(outpoint, &inflight->funding->outpoint))
			channel_internal_error(...);
		wallet_inflight_del(ld->wallet, channel, inflight);
		tal_free(inflight);
	}
```

Lightningd does not check `i_sent_sigs` either.

### Why the accepter always signs first

`do_i_sign_first` attributes the shared channel input to whoever added it (the initiator). Incoming splices set `accepter_relative = 0` and add no extra inputs (`next_splice_step` returns `NULL` for the accepter). Initiator input sum is the whole channel; accepter sum is 0. The accepter **SHOULD send `tx_signatures` first**.

Peer-initiated `stfu` is auto-accepted (`handle_stfu` sets `want_stfu` and echoes `stfu`). Peer-initiated `splice_init` is auto-acked.

### Attack

The attacker is an existing channel peer who advertised `option_splice` (CLN does this by default; a modified peer can too).

1. Send `stfu`, then `splice_init` (zero relative amount is enough; a no-op rebind of the funding outpoint).
2. Complete interactive construction. Victim runs `check_balances`, signs the splice (`hsmd` `handle_sign_splice_tx` has no amount checks), stores `last_tx`, sets `i_sent_sigs`, sends `tx_signatures`.
3. Instead of `tx_signatures`, send `tx_abort`.
4. Victim deletes the inflight and treats the splice as cancelled.
5. Attacker combines our signature with theirs and broadcasts the splice.

Old funding is spent by a transaction we no longer track. `funding_spent` only ignores spends that match a remaining inflight (`peer_control.c:2506-2521`); with the inflight gone it starts `onchaind`. `onchaind` does not treat a splice as mutual close (`is_mutual_close` requires shutdown scripts). The new output is a 2-of-2, not `to_remote`, so `handle_unknown_commitment` does not claim it.

Old commitments spend the old (now spent) outpoint. New commitments (`inflight->last_tx`) were deleted. Spending the new 2-of-2 needs the peer's funding signature. Result: **channel funds (and any splice-in UTXOs we contributed) stuck**.

Key rotation on splice makes recovery even harder: the inflight was the only place we stored the new remote funding key.

### Fix

- In the loop, call `have_i_signed_inflight(peer, itr)`, not `inflight`.
- After we have signed, refuse `tx_abort` and **keep watching** the inflight (do not `wallet_inflight_del`).
- Defense in depth: lightningd must refuse to delete an inflight with `i_sent_sigs` / a stored `last_tx`.
- Dual-open already refuses abort after remote tx-sigs (`openingd/dualopend.c:1534-1538`); splice should match that policy, and also refuse after *we* signed.

---

## Finding 2 — HIGH: `s64` channel balance wrap on a peer `update_add_htlc`

**Loss of funds:** yes, when the node then forwards or fulfills against the wrapped inbound HTLC
**Requires P2P:** yes (`update_add_htlc`). `--offline` blocks it.
**Confidence:** high that the wrap is reachable; high that the resulting commitment is consensus-invalid; medium-high that lightningd will then forward/pay. Needs a companion *outgoing* HTLC on the same channel so `commit_tx`'s `total_pay` assert does not abort.

### Root cause

Channel balances in `channeld` are `s64`:

```24:42:channeld/full_channel.c
struct balance {
	s64 msat;
};
...
static void balance_add_htlc(struct balance *balance,
			     const struct htlc *htlc,
			     enum side side)
{
	if (htlc_owner(htlc) == side)
		balance->msat -= htlc->amount.millisatoshis; /* Raw: balance */
}
```

`htlc->amount` is `u64`. `s64 -= u64` is unsigned 64-bit arithmetic. For a remote HTLC of `amount_msat = UINT64_MAX` and remote owed `R`:

`R - UINT64_MAX` wraps to `R + 1`.

`get_room_above_reserve` therefore sees *more* remote room, not less, and the "cannot afford" check passes.

Other gates that should stop this do not:

| Check | Why it fails |
|---|---|
| `max_htlc_value_in_flight` | Default `UINT64_MAX` (`lightningd/opening_common.c:150`). `amount_msat_greater(UINT64_MAX, UINT64_MAX)` is false. |
| `chainparams->max_payment` (`2^32-1` msat) | Enforced only for `sender == LOCAL` (`full_channel.c:711-715`). Peer amounts are unrestricted. Wumbo is default anyway. |
| `htlc_in_check` | Rejects zero, not "larger than channel". |
| `commit_tx` `total_pay <= funding` | Sums **to_local + to_remote only**, not HTLC outputs (`commit_tx.c:151-153`). |
| `bitcoin_tx_add_output` / wally | No `MAX_MONEY` check; `assert(output)` on `WALLY_OK`. |
| `hsmd` remote commitment sign | Signs the tx hash; no output-value check. |
| `check_fwd_amount` / `handle_localpay` | Require `incoming >= outgoing` / `incoming >= amt_to_forward`. `UINT64_MAX` inbound against a real onion amount **passes**. |

Comment at `full_channel.c:742-743` already notes that offered-sum overflow is possible "if they try to add a maximal HTLC", but the single-HTLC `UINT64_MAX` case does not overflow that sum.

### Companion HTLC (assert bypass)

With no other HTLCs, wrap inflates `owed[LOCAL]+owed[REMOTE]` by 1 msat and `commit_tx` asserts (`NDEBUG` is not set; this is a crash/DoS, not theft).

Two *remote* HTLCs cannot coexist with this amount: `amount_msat_add` of `1 + UINT64_MAX` fails and returns `CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED`.

A **local** (outgoing) HTLC of ≥ 1 msat *does* work: `sum_offered_msatoshis` is filtered by owner, and the local HTLC's −1 msat on `owed[LOCAL]` cancels the wrap's +1 on `owed[REMOTE]`. The assert passes. Routing nodes have outgoing HTLCs in the ordinary course; an attacker can also hold one (pay us / receive a hold invoice through this channel) before sending the maximal HTLC.

The commitment then has an HTLC output of `UINT64_MAX/1000` sat (~1.84e16), far above funding and `MAX_MONEY`. It serializes and signs. It cannot be mined.

### Attack sketch

Attacker is the previous hop, and colludes with the next hop (or is paying a victim invoice).

1. Ensure this channel has an in-flight HTLC we offered (≥ 1 msat).
2. Send `update_add_htlc(amount=UINT64_MAX)` with a normal onion (forward a real amount, or pay a real invoice).
3. Victim accepts, signs the invalid commitment, revokes the previous one.
4. lightningd does not re-check amount vs capacity (`peer_accepted_htlc`). `check_fwd_amount(UINT64_MAX, real_fwd)` / `handle_localpay` succeed. Victim forwards real funds or reveals a preimage.
5. Latest commitments cannot be broadcast. Previous ones are revoked. The fake inbound cannot be claimed on-chain. Outgoing settle is real.

Failing the inbound later wraps the `s64` back (the reverse add of `UINT64_MAX` restores remote owed). That does not recover the already-settled outgoing payment.

### Fix

- Reject peer `amount_msat` above channel capacity, `MAX_MONEY`, and `chainparams->max_payment` (apply the existing local check to `REMOTE` as well).
- Use `amount_msat` / saturating helpers in `balance_add_htlc` / `balance_remove_htlc`; never `s64 -= u64`.
- Cap `max_htlc_value_in_flight` to funding.
- In `commit_tx`, assert `to_local + to_remote + untrimmed HTLCs + fees + anchors == funding` (not just `to_local + to_remote <= funding`).
- lightningd must refuse inbound HTLCs larger than the channel before forwarding or fulfilling.

---

## Finding 3 — HIGH (architecture): HSM signs splices blindly; `channeld` admits missing theft checks

**Loss of funds:** not by itself; any hole in `check_balances` or Finding 1 is immediately signable
**Requires P2P:** yes
**Confidence:** high that validation is incomplete

```3858:3862:channeld/channeld.c
	/* DTODO Validate splice tx takes none of our funds in either:
	 * 1) channel balance
	 * 2) other side sneakily adding other outputs we own
	 */
```

After `tx_complete`, both accepter and initiator **overwrite** the funding output to a computed `both_amount` (`channeld.c:4348-4350`, `4607-4609`) and never re-check that the PSBT still conserves value against chain UTXOs.

`hsmd/libhsmd.c` `handle_sign_splice_tx` (lines 1447-1478) signs `SIGHASH_ALL` on the funding input with no output/amount checks.

`check_balances` is serial-id based and uses peer-supplied prevtx values. Fake prevtx amounts generally make *their* signatures invalid (segwit sighash includes value), so this is not a clean steal by itself. Combined with Finding 1, we sign first and then throw the tx away.

### Fix

HSM or `channeld` (both): the splice tx must spend our current funding, pay the expected 2-of-2 amount, and charge extra outputs to the peer using **wallet/UTXO amounts**. Re-run that check after `tx_complete` and immediately before `hsmd_sign_splice_tx`.

---

## Finding 4 — MEDIUM: `lowest_splice_amnt` uses total funding and writes the wrong slots

**Loss of funds:** not clean theft; can allow HTLCs that do not fit a pending splice-out, then race splice vs commitment
**Requires P2P:** yes
**Confidence:** high the accounting is wrong; medium for fund loss

```3728:3742:channeld/channeld.c
		s64 splice_amnt = inflights[i]->amnt.satoshis; /* should be inflights[i]->splice_amnt */
		...
		if (splice_amnt < view[LOCAL].lowest_splice_amnt[LOCAL])
			view[LOCAL].lowest_splice_amnt[LOCAL] = splice_amnt;
		if (splice_amnt < view[REMOTE].lowest_splice_amnt[REMOTE])
			view[REMOTE].lowest_splice_amnt[LOCAL] = splice_amnt; /* compares REMOTE, writes LOCAL */
		...
		if (remote_splice_amnt < view[REMOTE].lowest_splice_amnt[LOCAL])
			view[REMOTE].lowest_splice_amnt[REMOTE] = remote_splice_amnt;
```

`inflight->amnt` is the **new total capacity** (always ≥ 0), so our `lowest_splice_amnt[LOCAL]` is never set negative on splice-out. `get_room_above_reserve` uses that field to stop HTLCs that would not fit the worst inflight (`full_channel.c:430-440`). After a signed-but-unconfirmed splice-out, we can add outgoing HTLCs that fit the old channel and not the new one.

### Fix

Use `inflights[i]->splice_amnt` and consistent `[LOCAL]/[REMOTE]` index pairs. Add tests for splice-out + HTLC.

---

## Finding 5 — MEDIUM: splice `tx_signatures` overwrites inflight txid without checking

**Loss of funds:** not standalone; state confusion plus Finding 1
**Requires P2P:** yes
**Confidence:** high as a bug

```3968:3976:channeld/channeld.c
		if (!fromwire_tx_signatures(tmpctx, msg, &cid,
					    &inflight->outpoint.txid,  /* WRITE */
					    ...))
```

Dual-open **does** compare (`openingd/dualopend.c:1348-1355`). Splice does not. Witnesses are applied to our PSBT, so the peer cannot make us sign a different tx. They can desynchronize later abort/lock matching.

### Fix

Parse the peer txid into a local and `bitcoin_txid_eq` against the inflight.

---

## Finding 6 — MEDIUM: blinded-path fee wrap (incomplete `96f026ecc`)

**Loss of funds:** not principal theft on this tree; landmine if anyone later special-cases blinded hops
**Requires P2P:** yes (onion inside `update_add_htlc`)
**Confidence:** high the wrap is real; high it is currently blocked from paying out more than inbound

`96f026ecc` widened the blinded-path **denominator** to `u64` (CVE-class SIGFPE when `fee_ppm` was huge). The **numerator** still wraps:

```119:123:common/onion_decode.c
	p->amt_to_forward = amount_msat(ceil_div((amt - enc->payment_relay->fee_base_msat) * 1000000,
						 (u64)1000000 + enc->payment_relay->fee_proportional_millionths));
	p->outgoing_cltv = cltv_expiry - enc->payment_relay->cltv_expiry_delta;
```

- Underflow (`fee_base > amt`, `fee_base` is tu32 so only for inbound ≲ 4.295 BTC) produces `outgoing > incoming`.
- Multiply overflow (`amt ≳ 184.47 BTC`) produces `outgoing < incoming`.

`ceil_div` is still `(a + b - 1) / b`; a wrapped-to-tiny numerator yields a tiny/zero forward.

Anyone can encrypt `payment_relay` to the victim node id. The safer helper `amount_msat_sub_fee` exists and is unused on this path.

P2P forwards always go through `check_fwd_amount` (`lightningd/peer_htlcs.c:334-360`), which requires `incoming - advertised_fee >= outgoing`. Wrap-up is rejected. Wrap-down makes the node *keep extra* (not lose principal). CLTV underflow is similarly caught (`check_cltv`, `max_htlc_cltv`, locktime `< 5e8`).

### Fix

Use `amount_msat_sub_fee`. Reject `fee_base > amt`. Use overflow-checked multiply. Do not comment "if these values are crap, that's OK".

---

## Finding 7 — MEDIUM: watchtower splice / HTLC gap

**Loss of funds:** if the node is already spliced (or has revoked HTLC outputs) and then goes offline
**Requires P2P:** the splice/HTLCs happened while online; the cheat is an on-chain broadcast later
**`--offline`:** does **not** fully match the emergency wording. This is a gap in offline *protection*, not a live P2P steal.

```2553:2560:channeld/channeld.c
	if (pbase) {
		/* DTODO we need penalty tx's per splice candidate */
		ptx = penalty_tx_create(...);
	}
```

`penalty_tx_create` (`channeld/watchtower.c`) only spends the `to_them` output. It never spends revoked HTLC outputs.

### Fix

Penalty txs per splice candidate (as the DTODO says), including HTLC outputs.

---

## Finding 8 — LOW–MEDIUM: `amount_msat_add_sat_s64` / splice_locked raw `+=` overflow

**Loss of funds:** not demonstrated; crash / corrupt accounting
**Requires P2P:** peer can send `splice_init.opener_relative = INT64_MIN`

```400:408:common/amount.c
	if (b < 0)
		return amount_msat_sub_sat(val, a, amount_sat(-b));
```

Negating `INT64_MIN` is undefined. Practical result is likely `can_add` fail / abort.

After splice lock, lightningd does:

```1197:1199:lightningd/channel_control.c
	channel->our_msat.millisatoshis += splice_amnt * 1000; /* Raw: splicing */
	channel->msat_to_us_min.millisatoshis += splice_amnt * 1000;
	channel->msat_to_us_max.millisatoshis += splice_amnt * 1000;
```

`INT64_MIN * 1000` and large `s64 * 1000` overflow. Two's complement happens to work for normal negative splice-out amounts.

### Fix

Reject `opener_relative == INT64_MIN`. Use `amount_msat_add_sat_s64` in `channel_control.c` too.

---

## Finding 9 — LOW: simple close does not check our output amount

**Loss of funds:** not with current `simpleclosed` math; missing backstop
**Requires P2P:** `--experimental-simple-close` (optional feature)

`close_tx_check` (`lightningd/simple_close_control.c:35-90`) requires: one input spends funding, every output script is ours, theirs, or zero-value `OP_RETURN`. **No check that our output ≥ `our_msat` (rounded).**

`simpleclosed` builds amounts itself. As closee, closer's share is `funding_sats - local_sat`, not the `remote_sat` lightningd passed. Closer pays fees from their balance; they cannot set `closee_script` to something other than our last shutdown script.

### Fix

Require our output amount in `close_tx_check`.

---

## Finding 10 — LOW: interactive-tx ignores `channel_id`

`common/interactivetx.c` parses `cid` and never checks it. Dual-open does (`dualopend.c:1758`). `channeld` is one channel per process, so this is spec sloppiness, not cross-channel theft.

---

## What was checked and is not a clean P2P steal on this tree

| Area | Why not theft here |
|---|---|
| Malicious `commitment_signed` | CLN reconstructs the tx from its own view; peer signature is verified against that. |
| Dual-open `check_balances` | Funding output must equal opener+accepter; each side's inputs ≥ outputs+fees; serial parity on add/remove. |
| Splice `check_balances` (given serial parity) | Per-role `in ≥ out` including splice relatives; cannot splice out more than `owed`. Extra outputs charged to that serial_id. Serial-id wrong parity is rejected (`interactivetx.c`). |
| Dual-open `tx_abort` | Refuses abort after remote tx-sigs. (Still weaker than "after *we* signed".) |
| Mutual close `closingd` | Funder fee capped by our max feerate; fundee does not pay. |
| Zeroconf forget | Skips channels with `our_funds` or `msat_to_us_max`. Inherent zeroconf risk if we opted in. |
| Dual-open RBF lock-in | Mined inflight is applied, not `list_tail` (`90b58e816`). |
| `next_commitment_number == 0` | Failed closed (`eafdd9386`). |
| v1 funding-outpoint reuse | Bounded (`4b34ad332` / opening_control). |
| Peer-supplied splice prevtx inflation | Our splice sighash uses the real funding amount we set; a fake extra input invalidates *their* witness. |

---

## Already-public / already-fixed in this tree (not the bugs above)

- `96f026ecc` — blinded-path denominator u32 wrap → SIGFPE in `ceil_div`. Numerator wrap remains (Finding 6).
- `c2ba2358e` — offers recurrence `proportional_amount` miscalc (not P2P channel funds).
- `eafdd9386` — `channel_reestablish` `next_commitment_number==0` now fails the channel.
- `4b34ad332` — `openingd` `funding_satoshis` vs bitcoin supply.
- `90b58e816` — lock in the mined RBF inflight, not the latest one.

`v26.06.7` is not a distinct source commit from `v26.06.6` in this history.

---

## Recommended order of fixes

1. **Finding 1** — `have_i_signed_inflight(peer, itr)`; never delete / stop watching an inflight we signed. Same policy in lightningd.
2. **Finding 2** — reject oversized peer HTLCs; stop using `s64` for balances; tighten `commit_tx` conservation.
3. **Finding 3** — HSM + `channeld` splice output/balance checks after `tx_complete`.
4. **Finding 4** — `update_view_from_inflights` field and index fixes.
5. **Finding 5** — compare `tx_signatures` txid.
6. **Finding 6** — `amount_msat_sub_fee` on the blinded forward path.
7. **Finding 7** — watchtower splice candidates and HTLC penalties.
8. **Findings 8–10** — overflow, simple-close amount check, interactive `channel_id`.

Until 1 and 2 are patched, `--offline` is the correct operational mitigation: no listen, no reconnect, no peer messages, no new HTLCs or splices. It does not recover a splice that was already signed and then aborted, and it does not fill the watchtower splice gap for a splice that already confirmed.
