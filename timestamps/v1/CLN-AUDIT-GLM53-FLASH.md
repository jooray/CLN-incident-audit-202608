# Core Lightning — P2P Security Audit

**Repo state:** `master` @ `c1551c557`
**Scope:** peer-to-peer attack surface only (with `--offline` the node is safe): `connectd/`, `channeld/`, `closingd/`, `openingd/`, `dualopend/`, `gossipd/`, `lightningd/` peer message handling, `wire/`, `common/` parsing helpers.
**Method:** manual audit of all peer-message paths, cross-checked against recent upstream fixes (which this report treats as potentially incomplete). All findings below were verified against the source at the listed lines.

Severity ranking considers: remote reachability (no auth beyond an open channel / connection), attacker control of the triggering input, and fund impact.

---

## Executive summary

| # | Finding | File | Severity | Fund impact |
|---|---------|------|----------|-------------|
| 1 | `start_batch` with `batch_size == 0` → heap buffer overflow | `channeld/channeld.c:2428` | **Critical** | Forced close (fee burn, HTLC deadline risk); memory corruption |
| 2 | Simple close: peer-supplied `locktime` never validated → signed & broadcast permanently-unmineable close tx | `closingd/simpleclosed.c:329,428` + `lightningd/simple_close_control.c:37` | **High** | Entire channel balance locked indefinitely; no recovery path |
| 3 | Simple close: sub-dust closer output accepted → non-standard tx broadcast, same stuck state | `closingd/simpleclosed.c:379-384` | High | Channel lockup |
| 4 | `update_view_from_inflights` cross-wired view indices + wrong field | `channeld/channeld.c:3723-3744` | Medium | Splice balance tracking corruption → forced close / fee burn |
| 5 | `featurebits_unset` mask is a no-op (`0 << x`), zeroes whole byte | `common/features.c:548` | Medium | Unknown even bits accepted in `channel_type` negotiation |
| 6 | Operator-precedence bug in splice `check_balances` HTLC attribution | `channeld/channeld.c:3434` | Low | Latent misattribution |
| 7 | Residual integer overflow in blinded forward amount (`96f026ecc` incomplete) | `common/onion_decode.c:119-123` | Low | Fail-closed today; hardening |
| 8 | Unauthenticated `channel_update` accepted for our own channels (early path) | `gossipd/gossmap_manage.c:1099` | Low | Invoice mispricing / inbound-payment DoS |
| 9 | `query_channel_range` amplification DoS (no concurrency guard) | `connectd/queries.c:715` | Low | Availability |

---

## 1. CRITICAL — Heap buffer overflow via `start_batch` with `batch_size == 0`

**File:** `channeld/channeld.c:2417-2429` (handler), `:2480-2506` (`handle_peer_start_batch`)

```c
if (batch_size < 2 && last_inflight(peer))
        peer_failed_err(...);          // only rejects <2 when splices are inflight

msg_batch = tal_arr(tmpctx, const u8*, batch_size);
msg_batch[0] = msg;                    // OOB write when batch_size == 0
```

`batch_size` is an attacker-controlled `u16` read directly from the peer's
`start_batch` message (`fromwire_start_batch`, channeld.c:2484-2485).
`handle_peer_start_batch` performs **no sanity check** on it — it only validates
the `message_type` TLV. The sole bound check in `handle_peer_commit_sig_batch`
(`batch_size < 2`) is gated on `last_inflight(peer)`, so on any *ordinary*
channel (no splices in flight), `batch_size == 0` passes straight through.

`tal_arr(ctx, const u8*, 0)` allocates zero payload bytes; the subsequent
`msg_batch[0] = msg` writes 8 bytes past the allocation — a semi-controlled
heap pointer write into adjacent heap memory. The allocation loop
(`for (u16 i = 1; i < batch_size; i++)`) correctly does not run, so the
corruption goes unnoticed until tal/malloc metadata operations on that chunk.

**Exploit:** any peer with a single established channel sends
`start_batch { batch_size = 0, message_type = commitment_signed }` followed by
one `commitment_signed`. No feature negotiation gates this message.

**Impact:** heap memory corruption — crash of `channeld` at minimum. The master
treats a dead channeld as a protocol failure and force-closes the channel:
forced-close fee burn, HTLCs at deadline risk of preimage-loss, and a potential
exploitation primitive with heap grooming.

**Fix:** reject `batch_size == 0` (and consider `batch_size > inflights+1`)
unconditionally in `handle_peer_start_batch`.

---

## 2. HIGH — Simple close: unvalidated peer `locktime` → signed & broadcast permanently-unmineable closing tx

**Files:** `closingd/simpleclosed.c:326-333` (parse, no validation), `:428-450`
(tx built with peer locktime, signed), `common/close_tx.c:129-136`,
`lightningd/simple_close_control.c:37-91` (master validation omits locktime),
`:179-236` (store + broadcast).

As the **closee** in a mutual close with `option_simple_close` negotiated, we
parse `closing_complete`:

```c
if (!fromwire_closing_complete(tmpctx, msg, &their_cid, &closer_script,
        &closee_script, &fee_sat, &locktime, &tlvs))
```

`locktime` is **never checked**. It is passed to `make_close_tx(..., locktime)`
which builds the tx via `bitcoin_tx(ctx, chainparams, 1, 2, locktime)` with
input `nSequence = 0xFFFFFFFD` — a sequence value that *enforces* nLockTime
rather than disabling it. We sign it, send `closing_sig`, and tell master,
which stores it as `channel->last_tx` (`simple_close_control.c:179`) and
broadcasts it via `drop_to_chain` (`:234`).

**Exploit:** the peer sends `closing_complete` with
`locktime = 0xFFFFFFFE` (block height ≈ 4.29 billion — unreachable). We sign
and broadcast a transaction that enters the mempool but can **never be mined**.

**Fund-loss mechanism:** the funding outpoint is never actually spent, so
onchaind never starts and the channel sits in `CLOSINGD_COMPLETE` with the
entire balance frozen. Recovery paths are dead:

- `resolve_close_command()` is invoked immediately in
  `handle_simpleclosed_complete` (`simple_close_control.c:230`), disarming the
  `close` RPC's `unilateraltimeout` force-close watchdog.
- A fresh `close` RPC is refused because `channel_state_can_close()`
  (`closing_control.c:553`) excludes `CLOSINGD_COMPLETE`.

The attacker can later release the funds by double-spending with their
commitment tx — i.e., the victim's full channel balance is locked until the
attacker cooperates.

**Fix:** in `handle_closing_complete`, reject non-final locktimes (e.g. any
locktime > current height + small margin, or require 0); add locktime/finality
and fee/amount-conservation validation to `close_tx_check()`.

---

## 3. HIGH — Simple close: sub-dust/zero closer output accepted and broadcast

**Files:** `closingd/simpleclosed.c:371-384`, `common/close_tx.c:144-180`

As closee, the only fee bound is `fee_sat > remote_sat` → error. There is no
check that the closer's own output (`remote_sat − fee_sat`) is ≥ dust or
non-zero (unless `OP_RETURN`), and `create_simple_close_tx` never dust-trims
(unlike the legacy `create_close_tx`).

**Exploit:** the peer (closer) sends `closing_complete` with
`fee_sat = remote_sat − 1`, leaving their output at 1 sat (below dust). We sign
`closer_and_closee_outputs` and master broadcasts a non-standard transaction no
node relays → same permanent `CLOSINGD_COMPLETE` lockup as Finding 2, except
here the tx never even leaves our node usefully.

Combined with Finding 2, a malicious peer has trivial, always-available ways to
convert a cooperative close into a stuck channel.

**Related wart:** `master_got_sig` unconditionally overwrites
`channel->last_tx` on every `closing_sig` exchange, while the 1-hour broadcast
delay (`da67bf845`) is computed in the subdaemon from fee comparison — the
delay can end up applied to the *wrong* (lower-fee) tx, or re-broadcast
`last_tx` blindly after the peer's tx already confirmed
(`simple_close_control.c:188-192`).

**Fix:** enforce dust/zero-output trimming (mirroring `create_close_tx`) and
fee-range validation on the closee side before signing.

---

## 4. MEDIUM — `update_view_from_inflights`: cross-wired view indices and wrong field

**File:** `channeld/channeld.c:3723-3744`

```c
s64 splice_amnt = inflights[i]->amnt.satoshis; /* Raw: splicing */        // (a)
...
if (splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE])
        peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL] = splice_amnt;   // (b)

if (remote_splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL])
        peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE] = remote_splice_amnt; // (b)
```

Two defects:

- **(a)** `inflight->amnt` is the *total new funding*; the relative local delta
  is `inflight->splice_amnt` (used correctly elsewhere, e.g. channeld.c:1515,
  2302, 3124). Since the total is a large positive number and the slots start
  at 0, these comparisons never fire as intended.
- **(b)** The condition reads one slot and writes the mirror slot
  (copy/paste bug). `view[REMOTE].lowest_splice_amnt[LOCAL]` is never written.

**Consumer:** `get_room_above_reserve()` (`channeld/full_channel.c:418-454`)
uses these values in `add_htlc` capacity checks (`full_channel.c:802,839`).
With our pending splice-out never debited (`[REMOTE][LOCAL]` stays 0), we can
accept/send HTLCs that exceed post-splice capacity; at `splice_locked`,
`channel_update_funding` aborts with "local balance negative" →
`peer_failed_err` → forced close; or we sign splice-period commitments whose
`to_local` is dust-trimmed (fee burn).

**Exploitability:** requires HTLC updates while a splice is in flight —
practically reachable via `skip_stfu` RBF splices (channeld.c:5002-5008) and
daemon-restart paths (`channel_force_htlcs`, channeld.c:6988, bypasses
`add_htlc` validation). The authors' own DTODO at channeld.c:3859-3862
acknowledges incomplete splice output validation here.

**Fix:** use `inflights[i]->splice_amnt`, and make each condition read and
write the same slot.

---

## 5. MEDIUM — `featurebits_unset` mask is a no-op; zeroes the entire byte

**File:** `common/features.c:542-551`

```c
(*ptr)[len - 1 - bit / 8] &= (0 << (bit % 8));   // 0 << n == 0, always
```

Intended `~(1 << (bit % 8))`. As written, the whole byte is ANDed with 0.

**Impact:** the only caller is `channel_type_accept()`
(`common/channel_type.c:151-152`), which blanks the `OPT_SCID_ALIAS` (46) and
`OPT_ZEROCONF` (50) variant bits before an equality check against known channel
types. Bit 46 lives in the byte holding bits 40-47, so **unknown even bits
40-45/47** sent by a peer inside its `channel_type` are silently erased before
the equality check. Per BOLT #2, unknown even bits in `channel_type` MUST cause
rejection. Instead, CLN accepts the proposal and echoes it back
(`channel_type.c:155-163`), committing to a channel type containing unknown
bits — divergent behavior vs. other implementations and a negotiation-invariant
break. (Bit 50's byte is likewise fully cleared.)

**Fix:** `(*ptr)[len - 1 - bit / 8] &= ~(1u << (bit % 8));`

---

## 6. LOW — Operator-precedence bug in splice `check_balances` HTLC attribution

**File:** `channeld/channeld.c:3434`

```c
if (htlc_owner(htlc) == opener ? LOCAL : REMOTE)
```

Parses as `(htlc_owner(htlc) == opener) ? LOCAL : REMOTE` — comparing an enum
side against a boolean. Pending HTLCs are attributed to the wrong
initiator/accepter bucket, making the "splice-out does not exceed attributable
funds" check (channeld.c:3452-3467) permissively wrong for the initiator
whenever uncommitted offered HTLCs exist during a splice. Latent today (STFU
blocks adds during normal splices; totals are still conserved), but the
per-side sums are wrong and any future reliance on them inherits the inversion.

**Fix:** `htlc_owner(htlc) == (opener ? LOCAL : REMOTE)`.

---

## 7. LOW — Blinded-forward amount arithmetic: upstream fix `96f026ecc` incomplete

**File:** `common/onion_decode.c:119-123`

```c
p->amt_to_forward = amount_msat(ceil_div((amt - enc->payment_relay->fee_base_msat) * 1000000,
                                 (u64)1000000 + enc->payment_relay->fee_proportional_millionths));
p->outgoing_cltv = cltv_expiry - enc->payment_relay->cltv_expiry_delta;
```

The upstream fix only widened the denominator (SIGFPE). Remaining, fully
attacker-controlled wrap paths: `amt - fee_base_msat` u64 underflow when
`amount_in < fee_base_msat`; `(…) * 1000000` u64 overflow for amounts above
~184.47 BTC; `ceil_div`'s internal `a + b - 1` overflow
(`common/onion_decode.c:59-62`); and `cltv_expiry - cltv_expiry_delta` u32
underflow.

Downstream checks (`check_fwd_amount`, `peer_htlcs.c:334-360`; `check_cltv`,
`:374-383`) currently make these fail-closed — a crafted `payment_relay` can
only fail a single HTLC (mislabeled `invalid_onion_blinding`). No direct fund
loss today; flag because the code comment claims "the HTLC will fail", which is
not guaranteed for all crafted inputs, and any future consumer of
`p->amt_to_forward` bypassing `check_fwd_amount` would receive an unsanitized
value.

**Fix:** guard `amt >= fee_base_msat`, compute the relay math with saturation
or 128-bit intermediates, and check the CLTV subtraction for underflow.

---

## 8. LOW — Unauthenticated `channel_update` for our own channels (invoice mispricing)

**Files:** `gossipd/gossmap_manage.c:1099-1110`,
`lightningd/channel_gossip.c:1343-1390`

When our channel's `channel_announcement` is not yet in the gossmap (announce
window, startup, or the 72-block dying-channel window), a `channel_update`
targeting **our** scid is accepted if it is merely *signed by whoever sent it*
— with no check that the signer owns the referenced side of the channel, and
(`channel_gossip.c:1374`) the source-peer check applies only to private
channels. A connected peer can thus inject a self-signed update with
`fee = 0, cltv_delta = 0` (or absurd values) for our channel; it is persisted
(`wallet_channel_save`) and feeds BOLT12 `payment_relay`/`payinfo` construction
(`plugins/offers.c:373-389`, `offers_invreq_hook.c:355-430`).

**Impact:** inbound BOLT12 payments can be made to fail, or payers overcharged,
until a legitimate update replaces it — griefing/DoS of the invoice path, not
direct theft. Fix: check the direction bit against the signer in the early
path, and validate `source` for public-channel updates in
`channel_gossip_set_remote_update`.

---

## 9. LOW — `query_channel_range` amplification DoS

**File:** `connectd/queries.c:641-751`

Unlike `query_short_channel_ids` (concurrency-refused, throttled via
`bytes_this_second`), the channel-range reply path has no pending-query guard,
queues the full gossmap reply synchronously, and is not counted against
`gossip_stream_limit`. An authenticated peer can send thousands of ~30-byte
queries per second (default `incoming_stream_limit` is 1 MB/s), each forcing a
full gossmap sweep and MBs of queued replies → CPU/RAM exhaustion → crash →
forced channel closes. Availability only.

---

## Areas audited and found clean

- **connectd:** BOLT#8 noise handshake (`handshake.c`), cryptomsg framing/key
  rotation, `fromwire_*` bounds discipline, TLV parsing (`wire/tlvstream.c`),
  `bigsize` canonicality, init/feature negotiation, reconnect counters.
  (Websocket: `f0c702ed8` is complete for header names; remaining issues are
  functional-only — `int rlen` truncation, continuation-frame drops, mask-sync
  across partial reads.)
- **openingd/dualopend:** funding_satoshis bounds (`4b34ad332` complete),
  push_msat, `check_config_bounds`, channel_type negotiation (`edd22480b`
  complete apart from Finding 5's helper bug), dual-funding `check_balances`
  conservation, `handle_tx_sigs` mismatch aborts, next_funding reconnect
  (`7fb9a29fb` complete), `tx_abort` refused after `tx_signatures`.
- **closingd (legacy path):** closing_signed fee negotiation, dust-trim variant
  signature checks, quickclose range math.
- **onchaind:** timeout/success race, preimage verification, penalty
  construction.
- **HTLC forwarding core:** incoming HTLCs only forwarded after irrevocable
  commit (`peer_got_revoke`), `htlc_out_check` invariants, MPP accumulation
  overflow-safety, invoice/MPP amount checks, dust-HTLC fail-immediate
  (PR 919), CLTV checks, double-release guards.
- **gossipd:** channel_update signer↔direction binding in the gossmap path,
  cann node ordering, chain_hash checks, gossip store parsing, BOLT12
  invreq/signature handling.

## Recommended fix order

1. `batch_size == 0` reject (one line, critical, trivially reachable).
2. Simple-close: validate `locktime` (and dust on closer output) before
   signing; add locktime/finality checks to `close_tx_check()`.
3. `update_view_from_inflights` index/field corrections.
4. `featurebits_unset` mask fix.
5. Items 6-9 as hardening.

---

## Independent review (DeepSeek V4 Flash 0731, Aug 27 2026)

The above audit was independently re-verified line-by-line against the same
commit (`c1551c557`, `master`). **All 9 findings are real code-level bugs.**
No hallucinated vulnerabilities were found. Per-finding verdict:

| # | Verdict | Notes |
|---|---------|-------|
| 1 | Confirmed, Critical | `tal_arr(…, 0)` mallocs only the tal header (tal.c:469-490, plain `malloc`, no rounding); `msg_batch[0] = msg` writes 8 bytes past the block. Dispatch ungated (channeld.c:5164); no feature negotiation needed (post-channel_ready). "Exploitation primitive" overreach: value is a heap pointer, not attacker-controlled → crash/DoS, not RCE. |
| 2 | Confirmed, High | Full chain verified: locktime unvalidated (simpleclosed.c:329), flows into `create_simple_close_tx` (sequence 0xFFFFFFFD enforces it, close_tx.c:131-136), `bitcoin_tx_check` checks only serialization (tx.c:268). Recovery paths dead (peer_control.c:485, closing_control.c:553). **Factual slip:** Bitcoin Core rejects non-final txs at mempool acceptance ("non-final") — the tx never enters the mempool; stuck-channel impact identical. |
| 3 | Confirmed, High | Only `fee_sat > remote_sat` bound (simpleclosed.c:379-384); `close_tx_check` checks scripts only, no dust/amounts. 1-sat output → non-standard → never confirms. |
| 4 | Confirmed, Medium | `amnt` is total funding (channeld.c:4382), delta is `splice_amnt` (4384; 3730 already uses it as the local delta). Read/write slots cross-wired (3735-3736, 3741-3742); `[REMOTE][LOCAL]` never written. Consumer `get_room_above_reserve` (full_channel.c:418) confirmed. |
| 5 | Confirmed bug, severity overstated | `0 << (bit % 8) == 0` → whole byte zeroed (features.c:548); original proposal echoed (channel_type.c:162-163). Spec-compliance break with zero direct fund impact → **Low**, not Medium. |
| 6 | Confirmed, Low | C precedence inversion, active exactly when we are splice initiator. Latent; severity correct. |
| 7 | Confirmed, Low, **citation error** | `check_fwd_amount`/`check_cltv` live in **`lightningd/peer_htlcs.c:334/374`**, not `channeld/peer_htlcs.c` (no such file). Upstream `96f026ecc` diff verified — only widened denominator (fixed real SIGFPE); residual wraps fail closed today. |
| 8 | Confirmed, Low | Full chain verified: not-in-gossmap self-signed update (gossmap_manage.c:1101-1110) → `channel_gossip_set_remote_update` accepts for public channels (channel_gossip.c:1374-1383) → `updates.remote` → `listincoming` (gossmods_listpeerchannels.c:127-181) → BOLT12 payinfo (offers_invreq_hook.c:355-359). Needs announcement absent from gossmap (window). |
| 9 | Confirmed, Low | No concurrency guard (vs queries.c:315-321); full gossmap gather + queued replies; `gossip_stream_limit` is inbound-only. Availability-only. |

### Reviewer notes (grill)

- **Mempool claim (#2):** wrong as written — rejected at broadcast, not stuck in
  mempool. Same outcome; should be corrected.
- **"Exploitation primitive" (#1):** overreach. One 8-byte write of a heap
  pointer with no attacker control of the value is a crash/DoS primitive, not RCE.
- **Severity (#5):** does not meet the report's own ranking criteria (no remote
  fund impact, no DoS) — downgrade to Low.
- **Citations:** #7 file path wrong (`lightningd/` not `channeld/`); #2
  `drop_to_chain` is at simple_close_control.c:235, and the "store + broadcast"
  path is `handle_simpleclosed_closee_broadcast` (still correct, line refs off
  by one).
- **What holds up:** every line number spot-checked matched; the "clean" areas
  (noise handshake, framing, TLV bounds, legacy closingd, onchaind) are
  consistent with the source; #2/#3 are the nastiest — a routine,
  victim-initiated close becomes a permanent lockup via the new
  `option_simple_close` path.

**Priority:** fix #1 immediately (one-line guard), #2/#3 as high-priority
validation gaps, #4/#5 as quick correctness fixes, #6-9 as hardening. Nothing
is a hallucination; two factual slips and two debatable severities.

