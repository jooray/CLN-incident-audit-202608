# Core Lightning Security Audit — P2P Attack Surface

**Target:** `/home/juraj/tmp/lightning` @ `c1551c557` ("master", verified byte-identical to `ElementsProject/lightning` upstream at audit time)
**Scope:** Peer-to-peer reachable code paths only (`connectd`, `openingd`/`dualopend`, `channeld`, `closingd`/`simpleclosed`, `onchaind`, plus the `lightningd`/`common` code they drive). A node started with `--offline` is not exposed to anything below.
**Method:** Manual audit of all peer-message handlers and money paths, with every finding below re-verified by direct code reads against this tree.

---

## Executive summary

| # | Severity | Area | Title |
|---|----------|------|-------|
| 1 | **Critical** | closingd | Legacy mutual-close fee negotiation has no upper bound — peer can get us to sign a close burning **up to 100 % of our funder balance** to fees; poisons `channel->last_tx` so even a later unilateral close broadcasts the burning tx |
| 2 | **High** | channeld | `check_tx_abort()` checks the wrong variable (`inflight` vs `itr`) — peer can `tx_abort` a splice **after** receiving our `tx_signatures`, we delete the inflight, peer keeps a fully-signed tx spending our funding output |
| 3 | **High** | dualopend | RBF after a funding candidate has mined re-defeats the "lock in the mined inflight" fix — channel locks in a funding tx that never existed on-chain; phantom-balance drain of real outbound liquidity |
| 4 | **High** | dualopend/lightningd | `psbt_compute_fee()` `assert()` overflow via fabricated RBF prevtxs — **remote crash of lightningd** (whole node, all channels unwatched) |
| 5 | **Medium** | channeld | `update_fee` can drive the commitment to zero outputs → `assert(n > 0)` → channeld crash loop, channel bricked |
| 6 | **Medium** | dualopend | `tx_add_output` with `value > 21M BTC` → libwally assert → remote dualopend crash (missed by the `max_supply` fix 4b34ad332) |
| 7 | **Medium** | dualopend | `minimum_depth` bypass: reconnect after depth-1 makes dualopend retransmit `channel_ready` regardless of configured depth |
| 8 | **Medium** | channeld | `update_view_from_inflights()` — wrong variable + cross-wired side indices make splice reserve-headroom checks non-conservative |
| 9 | **Low** | channeld | `start_batch` with `batch_size = 0` → heap OOB write; unbounded synchronous batch reads stall the daemon |
| 10 | **Low** | channeld | Accepter path never stores negotiated splice feerate — min-fee checks vacuous (pinning/griefing) |
| 11 | Low | onchaind | Peer's spend of THEIR_HTLC never resolves a live fulfill proposal → onchaind hangs forever; duplicate-rhash preimage `return` should be `continue` |

Items 1–3 are directly exploitable for **loss of funds** by a malicious channel peer. Items 4–6 are remote crashes; in Lightning, crashing a node (especially `lightningd`, item 4) is a precursor to HTLC theft, since the victim cannot watch or penalize while down.

---

## Vulnerability 1 (Critical): Unbounded mutual-close fee — peer can burn 100 % of a funder's balance

**Files:** `closingd/closingd.c:376-379`, `:415-440`, `:479-485`, `:969-1038`; `lightningd/closing_control.c` (`closing_fee_is_acceptable`, `peer_received_closing_signature`); `lightningd/peer_control.c` (`sign_and_send_last`, `drop_to_chain`); signer backstop absent at `hsmd/libhsmd.c` (`handle_sign_mutual_close_tx` carries an explicit FIXME).

The legacy `closing_signed` negotiation has **no maximum-fee enforcement at any layer**, and the one safety bound that exists is destroyed by the peer's first high offer:

1. **Receive side accepts anything above the floor** (`closingd.c:376`):
   ```c
   /* Master sorts out what is best offer, we just tell it any above min */
   if (amount_sat_greater_eq(received_fee, min_fee_to_accept)) {
       status_debug("...offer is reasonable");
       tell_master_their_offer(&their_sig, tx, closing_txid);
   }
   ```
   The peer's signed tx is persisted as `channel->last_tx` (`closing_control.c`, `peer_received_closing_signature` → `channel_set_last_tx` + `wallet_channel_save`).

2. **`closing_fee_is_acceptable()` checks only the minimum** (`closing_control.c`):
   ```c
   min_fee = amount_tx_fee(min_feerate, weight);
   if (amount_sat_less(fee, min_fee)) { ... return false; }
   ...
   return true;   /* no maximum check anywhere */
   ```

3. **`adjust_feerange()` lets the higher-side peer raise our ceiling without limit** (`closingd.c:426-429`):
   ```c
   if (side == feerange->higher_side)
       ok = amount_sat_sub(&feerange->max, offer, AMOUNT_SAT(1));  /* max = offer - 1 */
   ```
   The initial cap (`init_feerange` → `max_fee_to_accept`, derived from our real `max_feerate` at `calc_fee_bounds:623`) is overwritten the first time the peer offers above it. There is no downward clamp; BOLT's "strictly between" monotonicity is assumed, never enforced (a FIXME at `:420-425` admits this).

4. **The "within 1 sat, agree" rule signs the peer's offer verbatim** (`closingd.c:484-485`):
   ```c
   if (amount_sat_greater_eq(min_plus_one, feerange->max))
       return remote_offer;
   ```

5. The only remaining bound is `close_tx()` (`closingd.c:73-78`): `fee <= out[opener]`. **When we are the funder, that bound is our entire channel balance.**

6. The bounded `do_quickclose()` path (`:687-722`, which would clamp to `min(our_max, their_max)`) is entered only `if (our_feerange && *their_feerange)` (`:969`). **The peer simply omits the `fee_range` TLV** from every `closing_signed` and the unbounded legacy loop runs — `use_quickclose` being enabled by default does not help.

**Attack (verified against the loop at `closingd.c:933-1038`):** we funded a channel (balance: us 1.0 BTC, them dust). We (or they) initiate a mutual close. The peer omits `fee_range` and offers `fee = 1.0 BTC` with a valid signature. `init_feerange` sets `higher_side = REMOTE`; `adjust_feerange(offer[REMOTE])` sets `max = 1 BTC - 1`; `adjust_offer` then escalates our *signed* offers by the configured step (default 50 %): ~0.5 BTC, 0.75 BTC, …, until `min+1 >= max`, at which point we return and **sign** `remote_offer` = 1.0 BTC (`send_offer` → `hsmd_sign_mutual_close_tx`, which deliberately performs no output/fee sanity checks — in-code FIXME). Roughly 50 round trips; every single one of our escalating offers is a fully valid signature the peer can countersign and broadcast at any moment — **agreement is not even required**.

The resulting tx pays our entire balance to miner fees (our output becomes 0 and is dropped; the peer still gets only `out[REMOTE]`). The peer profits directly if it mines or colludes with a miner (out-of-band fee recapture); otherwise it is unrecoverable burning of our funds.

**Poisoning persists past the negotiation:** every "acceptable" peer offer overwrote `channel->last_tx`. Any later `drop_to_chain` (including the `close` RPC's own `unilateraltimeout`) calls `sign_and_send_last(channel->last_tx, …)` (`peer_control.c:312-327`), which re-signs the stored high-fee mutual close via `hsmd_sign_commitment_tx` (whose only checks are "1 input, >0 outputs") and broadcasts it. Disconnecting or failing the channel does not escape the poisoned tx.

**Impact:** loss of up to 100 % of the local balance of any channel we funded, whenever the peer chooses to defect during mutual close. No user confirmation exists anywhere in the path.

**Fix direction:**
- Reject `received_fee > max_fee_to_accept` in `receive_offer` and enforce a maximum in `closing_fee_is_acceptable`.
- In `adjust_feerange`, never let `feerange.max` *increase*: clamp `offer` to the current max before adjusting.
- Never return a `remote_offer > max_fee_to_accept` from `adjust_offer`.
- Give `hsmd_sign_mutual_close_tx` the dust limit, fee range and balances so the signer can enforce policy (resolving the long-standing FIXME).

---

## Vulnerability 2 (High): `check_tx_abort` checks the wrong variable — peer can abort a splice after we signed it, and we delete the inflight

**File:** `channeld/channeld.c:1882-1896`

```c
inflight = NULL;
for (size_t i = 0; txid && i < tal_count(peer->splice_state->inflights); i++) {
    struct inflight *itr = peer->splice_state->inflights[i];
    if (!bitcoin_txid_eq(&itr->outpoint.txid, txid))
        continue;
    if (have_i_signed_inflight(peer, inflight)) {   /* BUG: should be `itr` */
        peer_failed_err(peer->pps, &peer->channel_id, "tx_abort"
                        " is not allowed after I have sent my"
                        " signature. ...");
    }
    inflight = itr;
}
```

`have_i_signed_inflight()` returns `false` for `NULL` (`channeld.c:1781`). On the first (normally only) matching inflight, `inflight` is still `NULL`, so the "no abort after we've signed" guard **never fires**. (With two matching inflights it would check the *previous* one — still wrong.) The mirror-image self-abort path is written correctly one hundred lines later (`splice_abort`, `channeld.c:1943`: `if (inflight && inflight->i_sent_sigs) peer_failed_err(...)`), proving the intent.

**Exploit path:** the peer negotiates a splice with us and waits until it has received our `tx_signatures`. At that point it can assemble a **fully-signed splice transaction spending the channel's current funding output** (our shared-input signature plus its own). It then sends `tx_abort` for that txid — callers pass the txid from `interactive_send_commitments` (`channeld.c:3157`), `resume_splice_negotiation` (`:3837`, `:3956`) and `peer_reconnect` (`:5857`). The broken guard lets it through; we ack the abort, send `CHANNELD_SPLICE_ABORT` to lightningd, which **deletes the inflight from the wallet DB** (`lightningd/channel_control.c` → `wallet_inflight_del`), and channeld restarts on the old funding.

**Loss-of-funds scenario:** our node forgets the splice ever existed and keeps operating on the old outpoint. The peer holds a broadcastable transaction that spends it. Broadcasting it (possibly much later, at the worst moment for us) makes every commitment we hold unbroadcastable (spent input) and moves the funds into a new 2-of-2 output our node no longer tracks (the record — including any rotated remote funding key — was deleted). The peer can additionally publish the splice-era commitment we signed during negotiation, rolling back payments routed to us after the splice. Best case: all channel funds stranded in an untracked output; realistic case: theft of post-splice value plus forced-close chaos.

**Fix:** one-word fix — `inflight` → `itr` at line 1887 — plus consider binding the context txid when `check_tx_abort` is invoked from the generic `peer_in` path.

---

## Vulnerability 3 (High): RBF after mining re-defeats the "lock in the mined inflight" fix — phantom funding lock-in

**Files:** `lightningd/dual_open_control.c:1029-1052` (the recent fix 90b58e816), `:1240-1260` (`wallet_update_channel`), `:3586-3612` (RBF branch of `handle_commit_ready`), `:4296-4304` (`peer_restart_dualopend`); `openingd/dualopend.c:3836-3855` (`handle_funding_depth`), `:3665-3686` (RBF start).

The recent fix pins the *mined* inflight onto the channel the moment its block is seen:

```c
/* dual_funding_found */
if (inflight->channel->state == DUALOPEND_AWAITING_LOCKIN)
    update_channel_from_inflight(ld, inflight->channel, inflight, false);
```

But that protection is undone by **any RBF that reaches `commit_ready` afterwards**, because `wallet_update_channel` unconditionally overwrites the channel's funding state with the new candidate:

```c
/* wallet_update_channel */
channel->funding = *funding;
channel->funding_sats = total_funding;
channel->our_funds = our_funding;
...
```

The only gate on the RBF branch is `assert(channel->state == DUALOPEND_AWAITING_LOCKIN)` — and the state **stays** `DUALOPEND_AWAITING_LOCKIN` until the peer sends `channel_ready`, which a malicious initiator can withhold indefinitely. The window is not racy; it is open-ended and fully peer-controlled.

Two lock-in paths then select the unmined candidate:

1. **No reconnect needed:** `dualopend_tell_depth` (`:996`) sends `towire_dualopend_depth_reached(NULL, depth)` — *no txid* — and dualopend's lock-in decision uses `state->channel->funding`, which after the RBF is candidate B (rebuilt from the latest tx_state at `dualopend.c:2204`/`:2835`). When the attacker finally sends `channel_ready` for B, `handle_channel_ready` passes (v2 `channel_id` is key-derived, stable across RBFs), `handle_channel_locked` transitions to `CHANNELD_NORMAL` on `channel->funding` = B and calls `wallet_channel_clear_inflights` — the mined inflight A is forgotten forever. The later depth callback for A no-ops (`opening_depth_cb:1011`: state != AWAITING_LOCKIN → DELETE_WATCH). Our broadcast of B fails (double-spent by mined A) but is only logged.

2. **Reconnect path:** after the RBF clobber, `peer_restart_dualopend` selects the inflight by `channel->funding.txid` (= B), and `channel_ready[LOCAL]` is forced from `channel->scid != NULL` (which was set by mined A) — so a reconnect alone completes the lock-in of B.

**Loss-of-funds scenario:** we are the accepter in a v2 open; the attacker is the initiator (only initiators may RBF, enforced at `dualopend.c:3665`). Attempt A (small, real inputs) mines normally. The attacker delays `channel_ready`, RBFs to B with a vastly inflated `funding_output_contribution` covered by **fabricated `tx_add_input` prevtxs** — never verified on-chain because `require_confirmed_inputs` defaults to false and `is_segwit_output` only checks script shape. B locks in per above. The channel reaches `CHANNELD_NORMAL` with `scid` = scid(A) — a real UTXO with the *same* 2-of-2 keys — but our stored `last_tx` spends B's outpoint, which does not exist: **we can never unilaterally close**, and the real funds in A require the attacker's cooperation to recover. Worse, the attacker routes self-payments *attacker → phantom channel → us → real channels → attacker*: we pay out real satoshis and receive phantom balance, draining our real outbound liquidity. This is exactly the failure mode the fix commit describes, reproduced post-fix through the RBF path.

Related sub-issue: `lock_signer_outpoint(&state->channel->funding)` (`dualopend.c:479`) locks the *latest* attempt's outpoint into hsmd even when the mined one won — a no-op for the stub signer, but it bricks the channel with external validating signers (VLS).

**Fix direction:** refuse RBF (peer- and user-initiated) once `channel->scid` is set / a funding watch has fired; make `wallet_update_channel` refuse to clobber a mined-pinned `channel->funding`; bind the mined txid into `dualopend_depth_reached` and have dualopend verify it before sending `channel_ready`/`lock_signer_outpoint`.

---

## Vulnerability 4 (High): Remote crash of `lightningd` via `psbt_compute_fee` overflow in the RBF validation path

**Files:** `lightningd/dual_open_control.c:2367` (`handle_validate_rbf`), `bitcoin/psbt.c:1009-1020` (`psbt_compute_fee`).

```c
/* handle_validate_rbf */
candidate_fee = psbt_compute_fee(candidate_psbt);

/* psbt_compute_fee */
for (size_t i = 0; i < psbt->num_inputs; i++) {
    input_amt = psbt_input_get_amount(psbt, i);
    ok = amount_sat_add(&fee, fee, input_amt);
    assert(ok);
}
```

Input amounts are read from **peer-supplied prevtxs** (`psbt_input_get_amount` → `prev_tx->outputs[idx].satoshi`). `tx_add_input` parses the prevtx with `wally_tx_from_bytes`, which is a deserializer and does **not** range-check output values against the 21M supply (the rejection documented in #9225 / commit 4b34ad332 happens at output *construction*, not parsing). Two crafted inputs with ~2^63-sat outputs overflow the sum and the `assert` fires **in lightningd** — a full-node remote crash.

The trigger ordering works because `rbf_wrap_up` asks lightningd to validate the RBF (`towire_dualopend_rbf_validate`, `dualopend.c:3416`) **before** dualopend runs its own overflow-checked `check_balances` (`:3438-3442`), which would have caught the same overflow cleanly. Reachable by any peer with a v2 channel in `DUALOPEND_AWAITING_LOCKIN` under default configuration.

**Impact:** the whole node goes down — no channel watching, no penalty, no HTLC resolution for *every* channel until manual restart. This is the classic "node-wide DoS as a precursor to HTLC theft" primitive. **Fix:** replace the asserts in `psbt_compute_fee` with a checked API, and/or bound input amounts at `tx_add_input` time.

---

## Vulnerability 5 (Medium): `update_fee` can drive a commitment to zero outputs → `assert(n > 0)` crash loop

**Files:** `channeld/commit_tx.c:398`, `channeld/full_channel.c:1342-1430` (`can_opener_afford_feerate`, `channel_update_feerate`).

`commit_tx()` asserts at least one output survives dust trimming:

```c
/* This means there must be at least one output. */
assert(n > 0);
```

but the only guard on the fee-update path, `can_opener_afford_feerate()`, checks the opener's **pre-fee** balance against `reserve + fee` — it never checks that any output survives trimming post-fee (anchors don't save you: they're only added `if (to_local || untrimmed != 0)`). `htlc_dust_ok()` is skipped for default anchor channels.

**Attack:** attacker (opener) opens a small lopsided channel to the victim (victim balance < dust). During a moderate-fee period (`feerate_max` is 10× any historical estimate, `UINT_MAX` if estimates unknown), the attacker sends an `update_fee` such that `reserve ≤ opener_balance − fee < dust` — a band that always exists — which passes `can_opener_afford_feerate`. On the next `commitment_signed`, the victim builds its commitment: `to_local` trimmed, `to_remote` trimmed, no HTLCs, no anchors → `n == 0` → **channeld SIGABRT**. The fee state is already committed/persisted, so every reconnect re-crashes: the channel is bricked in a crash loop.

Self-inflicted variant: when *we* are the opener, `approx_max_feerate()` (`full_channel.c:1260`) has the identical blind spot, so an organic fee spike on a small lopsided channel makes our own node crash on its own `update_fee`.

**Impact:** remote DoS / funds stranding (the last valid commitment remains closeable, so direct theft is bounded; the value at risk is the sub-dust balance plus liveness). **Fix:** reject any feerate that would leave a zero-output commitment, in both `channel_update_feerate` and `approx_max_feerate`.

---

## Vulnerability 6 (Medium): `tx_add_output` amount > total supply → remote dualopend crash

**Files:** `openingd/dualopend.c:1979-1987` (`run_tx_interactive`, `WIRE_TX_ADD_OUTPUT`), `bitcoin/psbt.c:261-272` (`psbt_add_output`), `bitcoin/tx.c` (`wally_tx_output` NULL for > `max_supply`).

```c
amt = amount_sat(value);            /* peer-controlled u64, unbounded here */
if (!is_known_scripttype(scriptpubkey, ...)) ...
out = psbt_append_output(psbt, scriptpubkey, amt);
```

libwally refuses to construct outputs above the 21M BTC supply; `wally_psbt_add_tx_output_at` then fails and `psbt_add_output` does `assert(wally_err == WALLY_OK)` → **abort()**. Commit 4b34ad332 bounded `funding_satoshis` in `open_channel2`/`accept_channel2` but missed this interactive-tx field. Any connected peer can crash dualopend during an initial v2 open or RBF; repeatable on every reconnect (persistent open/RBF denial of service, and a crash-primitive on the funds-handling path).

**Fix:** reject `value > chainparams->max_supply` in the `WIRE_TX_ADD_OUTPUT` handler (mirror `max_channel_funding`). Also grep channeld's splice interactive-tx for the same pattern.

---

## Vulnerability 7 (Medium): `minimum_depth` bypass — reconnect makes dualopend send `channel_ready` at 1 confirmation

**Files:** `lightningd/dual_open_control.c:4343` (`peer_restart_dualopend`), `:1036-1039` (`dual_funding_found` → `depthcb_update_scid`); `openingd/dualopend.c:4070-4075` (`do_reconnect_dance`).

On reconnect, dualopend is reinitialized with `channel_ready[LOCAL]` computed as:

```c
channel->scid != NULL,
```

but `channel->scid` is set at **first block inclusion (depth 1)**, not at `minimum_depth`. dualopend then retransmits `channel_ready` unconditionally (`do_reconnect_dance`). A peer can force this path at will by dropping and re-establishing the P2P connection (`peer_control.c` restarts dualopend for `DUALOPEND_AWAITING_LOCKIN` channels on every reconnect). Combined with a peer whose own `minimum_depth` is 1 (their `channel_ready` arrives legitimately at depth 1), **any reconnect at depth 2 locks the channel in below our configured `minimum_depth`** (default 3) — even without active malice. The v1 path is *not* affected (channeld's `handle_funding_depth` checks `depth < minimum_depth` before sending).

**Loss-of-funds scenario:** `minimum_depth` exists to survive short reorgs. If the funding tx is reorged out after this premature lock-in, the funding output ceases to exist while the channel is `CHANNELD_NORMAL`; both commitments spend a nonexistent outpoint and HTLCs forwarded during the window are unrecoverable.

**Fix:** pass the actual depth/`channel_ready` state (e.g. recompute `channel->scid != NULL` only after `minimum_depth` was reached, or persist the real `channel_ready[LOCAL]` instead of deriving it from the scid).

---

## Vulnerability 8 (Medium): `update_view_from_inflights` — wrong variable and cross-wired side indices break splice reserve checks

**File:** `channeld/channeld.c:3723-3742`; consumer `get_room_above_reserve`, `channeld/full_channel.c:418-467`.

```c
s64 splice_amnt = inflights[i]->amnt.satoshis; /* total new funding, always >= 0 */
s64 funding_diff = sats_diff(inflights[i]->amnt, peer->channel->funding_sats);
s64 remote_splice_amnt = funding_diff - inflights[i]->splice_amnt;

if (splice_amnt < peer->channel->view[LOCAL].lowest_splice_amnt[LOCAL])
    peer->channel->view[LOCAL].lowest_splice_amnt[LOCAL] = splice_amnt;              /* never fires: >= 0 vs initial 0 */

if (splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE])
    peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL] = splice_amnt;             /* compares [REMOTE], stores [LOCAL] */

if (remote_splice_amnt < peer->channel->view[LOCAL].lowest_splice_amnt[REMOTE])
    peer->channel->view[LOCAL].lowest_splice_amnt[REMOTE] = remote_splice_amnt;      /* only consistent line */

if (remote_splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL])
    peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE] = remote_splice_amnt;     /* reads [LOCAL], stores [REMOTE] */
```

Three distinct errors: (1) `splice_amnt` is the **total** new funding amount, not the relative delta (`inflight->splice_amnt`) used everywhere else — since it is always ≥ 0 and `lowest_splice_amnt[]` initializes to 0 (`channeld.c:459-462`), the two LOCAL entries are **never updated**: the "reserve headroom must absorb a pending splice-out" check is dead for the local side. (2) compares `[REMOTE][REMOTE]` but stores `[REMOTE][LOCAL]`. (3) with ≥2 concurrent RBF inflights the cross-wired lines keep the *last* negative value instead of the *minimum*.

The consumer (`get_room_above_reserve`, which assumes the value is "always negative or 0") subtracts `-lowest_splice_amnt[side]` from `owed[side]` before enforcing the reserve on every `update_add_htlc`. While a splice is unconfirmed, balance checks are therefore non-conservative: we can keep routing/adding HTLCs against our pre-splice balance, and at `splice_locked` `channel_update_funding` hits "would make balance negative" → `peer_failed_err` → unilateral close with HTLCs in flight. A peer controls the timing (it decides when its splice confirms) and profits from our forced close. Called on restart too (`channeld.c:6996`), so corrupted values persist.

**Fix:** use `inflights[i]->splice_amnt` for the LOCAL entries, make compared/assigned indices consistent, and add a unit test with two concurrent negative-delta inflights.

---

## Vulnerability 9 (Low): `start_batch` with `batch_size = 0` → heap OOB write; unbounded blocking batch reads

**File:** `channeld/channeld.c:2387-2506` (`handle_peer_commit_sig_batch`, `handle_peer_start_batch`).

```c
msg_batch = tal_arr(tmpctx, const u8*, batch_size);   /* batch_size == 0 -> zero-length array */
msg_batch[0] = msg;                                   /* OOB write of one pointer */
```

`handle_peer_start_batch` applies no lower bound to the peer-supplied u16 `batch_size` (only a TLV `message_type` check). With no splice inflight (the `batch_size < 2 && last_inflight(peer)` guard at `:2423` doesn't fire), `start_batch(batch_size=0)` followed by any `commitment_signed` triggers an 8-byte OOB write just past a zero-length tal allocation — UB; benign on glibc by luck, a crash/corruption primitive under a hardened allocator. Additionally, `batch_size` (up to 65535) controls how many peer messages we synchronously `peer_read` in a row; during this loop the master fd is not serviced, so a peer sending a large batch then going silent wedges the channel daemon against user-initiated close/HTLC-fail commands.

**Fix:** reject `batch_size < 1`, cap the count, and bound the batch read with a timeout.

---

## Vulnerability 10 (Low): Splice accepter path never stores the negotiated feerate — min-fee checks are vacuous

**File:** `channeld/channeld.c` — `splice_accepter` (4198-4400) vs `check_balances` (3595-3598).

The peer's `funding_feerate_perkw` is parsed into a local and only lower-bound checked; it is **never assigned** to `peer->splicing->feerate_per_kw` (only the local-initiator path sets it, `:4983`; `splicing_new` initializes it to 0). `check_balances` then computes `min_initiator_fee`/`min_accepter_fee` at feerate 0 → fee 0. A splice initiator can announce a normal feerate in `splice_init`/`tx_init_rbf` and then construct a transaction paying near-zero absolute fee; our solvency checks still pass and we sign it. The splice tx can sit unconfirmable indefinitely, pinning the channel with inflight commitments (compounds with #8) and enabling RBF churn. No direct theft (the max-fee direction is still enforced via `max_accepter_fee`), but reliable griefing/pinning.

---

## Vulnerability 11 (Low): onchaind — unresolved THEIR_HTLC spends hang the channel; duplicate-rhash preimage handling bug

**File:** `onchaind/onchaind.c:1225-1247`, `:1478-1485`.

1. In `output_spent()`, a peer's spend of a `THEIR_HTLC` output is only annotated, never resolved ("we ignore this timeout tx"). That assumption breaks once `handle_preimage()` has replaced the ignore-proposal with a real fulfill proposal (`:1490-1492`): if the peer's HTLC-timeout spend confirms instead of our fulfill, the output never becomes `resolved`, `WIRE_ONCHAIND_ALL_IRREVOCABLY_RESOLVED` is never sent, and lightningd keeps the channel in ONCHAIN state forever. The asymmetric `OUR_HTLC` case (`:1282-1300`) does resolve — strongly suggesting an oversight. Liveness/bookkeeping impact (the HTLC value is legitimately the peer's by then), triggerable by a peer engineering a confirming race.
2. `handle_preimage()` `return`s (instead of `continue`) when the first matching output was already resolved non-SELF, skipping later duplicate-payment-hash HTLCs — a still-unresolved duplicate never gets its fulfill proposal and times out back to the peer. Contrived, but one full HTLC is at stake.

---

## Additional hardening notes (no direct loss-of-funds demonstrated)

- **simpleclosed.c**: the "fee > closer's balance → fail" BOLT rule is skipped when the closer's script is OP_RETURN (`:379-384`); the unchecked fee then feeds the 1-hour broadcast-delay heuristic (`:774-786`) → forced delay griefing. Also: `anysegwit = true` hardcoded when validating the peer's closer script (`:326`); PSBT keypath attached to the wrong output for the closee (`common/close_tx.c:153-160`); missing `assert(total_out <= funding)` present in the legacy builder.
- **channeld**: most peer handlers parse `channel_id` without comparing it to the channel (mitigated today by connectd's per-channel demux); `channel_fulfill_htlc` assigns `htlc->r` before the irrevocability checks (`full_channel.c:1004`); bare `tx_abort` kills channeld at any time even with no splice (`:1872`, callers `:5108`/`:5211`); `update_add_htlc` is accepted after `shutdown`; `update_blockheight` has no upper bound and its stored value can later wrap `peer_height + 1008` into a spurious self force-close (`:6549-6559`); `update_hsmd_with_splice` hands stale funding keys and a sign-flipped `push_value` to external signers.
- **dualopend**: accepter role performs no min/max feerate validation on the opener's proposed feerates (unlike the legacy fundee path); `handle_tx_sigs` doesn't check `channel_id`; `require_confirmed_inputs` counts mempool outputs as confirmed (bcli `gettxout` without `include_mempool=false`) and defaults to false; lease-fee accounting is silently dropped across RBF; a depth watch is dropped if funding mines while state is `DUALOPEND_OPEN_COMMITTED`.
- **lightningd**: pending `htlc_accepted` hook payload holds bare `hin`/`channel` pointers with no lifetime link — a plugin that responds after the channel is deleted (e.g. after a force-close resolves) is a use-after-free window (`peer_htlcs.c:1545-1597`, consumed at `:1263-1316`); `--cltv-delta 0` would turn a policy check into a remote `fatal()` crash (`htlc_end.c:185-188`); wrap-based arithmetic in `handle_blinded_forward` (`common/onion_decode.c:119-123`) is currently survivable only because `forward_htlc`'s checks reject every garbage value — make the subtractions checked.
- **common**: `initial_commit_tx.c` uses `NULL` as the `direct_outputs[LOCAL]` marker, colliding with anchor outputs (phantom penalty base for revoked commitment #0 in edge cases, bounded to < 330 sat by dust checks) — use non-NULL dummies like `commit_tx.c:142-144`; `htlc_trim_feerate_ceiling` can u32-wrap at absurd feerates; latent NULL-deref if `htlc_tx()` fee-subtraction ever fails (`full_channel.c:260-289`); `create_simple_close_tx` lacks the legacy `total_out <= funding` assert; lightningd-side `close_tx_check` validates scripts but not amounts.
- **closingd**: `channel_id` from wire messages is never compared to the expected one; `simpleclosed` ignores peer `error`/`warning` frames; remote shutdown script is overwritten on every `shutdown` including mid-close reconnects (verified non-redirecting of *our* funds, but the first-script-reuse rule is unenforced); HSM signs mutual closes blindly (this is why Finding 1 has no signer-side backstop).

## Areas explicitly audited and found sound

- `handle_peer_commit_sig` / `handle_peer_revoke_and_ack` (commitment reconstruction purely from persisted state, `check_tx_sig` + `hsmd_validate_commitment_tx` double-check, revocation secret validated before state mutation, persistence-before-revoke ordering, batch handling fails closed).
- HTLC lifecycle (id-reuse detection, double-fulfill/fulfill-after-fail, full 32-byte preimage compare, removal-side accounting).
- Forwarding policy: `check_fwd_amount` (fee coverage, correct direction/units), `check_cltv` (delta + too-soon/too-far), per-hop and MPP/final-hop invariants, irrevocable-commit-before-invoice-resolution.
- Reestablish logic post-eafdd9386 (zero-commitment rejection, ±1 windows, future-secret data-loss path, lightningd-side bookkeeping).
- Legacy `openingd.c` (funder & fundee): bounds, key ordering, first-commitment `check_tx_sig`, funding watch keyed to the exact expected script/outpoint/amount (mismatched funding can never reach lock-in).
- `common/amount.c` (overflow-checked, `WARN_UNUSED_RESULT`), `permute_tx.c` (deterministic BIP69 order both sides), `fee_states.c` post-saturation (state machine can't carry a feerate one side never agreed to; consumers fail closed), `common/htlc_tx.c` locktime/sequence/sighash conventions.
- onchaind penalty machinery: revoked-state recognition ordering, keyset derivation from the recovered secret, penalty witness shapes, feerate grinding, `cltv+1` broadcast timing, 100-block irrevocability, RBF/reorg handling via lightningd-driven replay.

## Suggested fix priority

1. **#1** (closingd fee bound) — direct, silent, 100 %-of-balance loss; trivially triggered by any channel peer.
2. **#2** (`check_tx_abort`) — one-word fix for a signed-splice theft primitive.
3. **#3** (RBF-after-mine) — reopens the exact class the last fix targeted; add a regression test.
4. **#4 / #6** (remote `lightningd`/dualopend crashes) — replace assert-based amount paths with checked ones at the trust boundary.
5. **#5, #7, #8** — liveness/crash-loop and policy-bypass fixes with tests.
6. Remainder as hardening.
