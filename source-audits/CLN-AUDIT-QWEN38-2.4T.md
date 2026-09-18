# Core Lightning (CLN) — P2P Funds-Path Security Audit

- Auditor: automated static audit (opencode / Qwen 3 8B 2.4T)
- Target: `/home/juraj/tmp/lightning`
- Snapshot: `master` @ `c1551c557` (`.version` = `v26.06.6`, ahead of the `v26.06.6` tag by ~10 commits)
- Scope: peer-to-peer code paths that move or commit funds (HTLC forwarding / blinded paths,
  commitment & revocation state machine, channel open/splice/close signing, onchain resolution,
  HSM signing policy, amount/fee arithmetic). Local-RPC-only and gossip DoS surfaces were
  de-prioritized, per the constraint that `--offline` must make the node safe.
- Working tree: clean, byte-identical to `origin/master` (no local/uncommitted modifications).

---

## Executive summary

The single most significant P2P-reachable, funds-path defect in this snapshot is an
**integer overflow / underflow in the blinded-path forwarding amount computation** in
`common/onion_decode.c` (`handle_blinded_forward`). The amount to forward is computed from
`payment_relay` fields that are chosen by the **payment recipient** and delivered to the
intermediate node inside `encrypted_recipient_data`, i.e. attacker-influenced data that arrives
over the peer-to-peer HTLC protocol.

A partial fix was already applied in this tree (`96f026ecc lightningd: check value overflow for
forward amounts`), but that fix is **incomplete**: it widened only the *denominator* to `u64`
(stopping a divide-by-zero crash). The *numerator* and the *CLTV* subtraction still perform raw,
unchecked arithmetic that can wrap. The pre-fix behaviour is a remotely triggerable crash of
`lightningd` (denial of service); the residual wrapped arithmetic sits directly in a
funds-critical amount computation.

The **splice implementation is the least-hardened funds path in the snapshot** and carries several
**unfixed** defects (Findings 2 and 3):
- `update_view_from_inflights()` compares an absolute funding total against a relative
  `lowest_splice_amnt` (dead updates) and swaps the REMOTE-view indices, so a pending splice-out can
  be under-counted in `get_room_above_reserve()`, which gates HTLC acceptance → plausible
  over-commitment (Finding 2).
- The splice tx is signed with no balance re-validation (explicit `DTODO` in
  `resume_splice_negotiation`) and the HSM `handle_sign_splice_tx` blind-signs with no checks,
  leaving `check_balances()` as the sole economic validation (Finding 3).
- The BOLT-mandated splice reserve check is unimplemented (`DTODO` in `check_balances`).
These are the closest things found to a direct funds-integrity bug.

A fourth **unfixed** issue is in legacy mutual close (Finding 4): the close fee — which is deducted
from the **opener's** output — is validated only against a *minimum* (both in
`closingd/closingd.c:receive_offer` and in the master's `closing_fee_is_acceptable`). There is no
maximum bound, so a malicious closee can drive the fee up to the opener's entire balance, which the
opener node will store and broadcast as `last_tx`, burning its whole balance to miner fees
(griefing-class loss of funds).

All other P2P defects recently fixed in this tree (zero `next_commitment_number` on reestablish,
`marginal_feerate` overflow, `funding_satoshis` above total supply) are in the same
"peer-controlled integer with missing bounds check" family and are crash/DoS class.

**Impact classification (see detailed analysis):** the demonstrated, reliable primitive today is
a remote crash (DoS) of `lightningd`, which by itself is not a direct balance debit. Direct
balance loss through this exact path is currently held in check by downstream fee/CLTV validation
in `lightningd/peer_htlcs.c`; however the wrapped arithmetic is a latent funds-correctness bug,
and the crash primitive is a building block in compound attacks (see "Impact" below). This is the
area the project itself is actively patching, which corroborates it as the live attack surface.

---

## Primary finding — Blinded-path forwarding amount integer overflow/underflow

### Location
`common/onion_decode.c`, `handle_blinded_forward()` (approx. lines 64–125). Called from
`onion_decode()` for any non-final hop of a blinded route; reached via
`lightningd/peer_htlcs.c:peer_accepted_htlc()` when an incoming HTLC is processed.

### Code under audit
```c
static u64 ceil_div(u64 a, u64 b)
{
	return (a + b - 1) / b;
}

static bool handle_blinded_forward(..., struct amount_msat amount_in, u32 cltv_expiry,
				   const struct tlv_payload *tlv,
				   const struct tlv_encrypted_data_tlv *enc, ...)
{
	u64 amt = amount_in.millisatoshis; /* Raw: allowed to wrap */
	...
	/* amt_to_forward = ceil((amount_msat - fee_base_msat) * 1000000 /
	 *                       (1000000 + fee_proportional_millionths)) */
	/* If these values are crap, that's OK: the HTLC will fail. */
	p->amt_to_forward = amount_msat(ceil_div(
			(amt - enc->payment_relay->fee_base_msat) * 1000000,
			(u64)1000000 + enc->payment_relay->fee_proportional_millionths));
	p->outgoing_cltv = cltv_expiry - enc->payment_relay->cltv_expiry_delta;
	return true;
}
```

Field types (from `wire/onion_wire.csv`, `encrypted_data_tlv.payment_relay`):

| field | wire type |
|---|---|
| `cltv_expiry_delta` | `u16` |
| `fee_proportional_millionths` | `u32` |
| `fee_base_msat` | `tu32` (≤ u32 max) |

These values are part of `encrypted_recipient_data`, which the **recipient** constructs for each
blinded hop (encrypted to that hop's path key). An intermediate node decrypts them but does not
choose them. A malicious recipient therefore controls all three fields for the victim hop.

### The defects

1. **Numerator underflow.** `(amt - fee_base_msat)` is unsigned. If the recipient sets
   `fee_base_msat > amount_in`, the subtraction wraps to a value near `2^64`. (`amt` is explicitly
   annotated `Raw: allowed to wrap`.)

2. **Numerator overflow.** `(... ) * 1000000` is a `u64` multiply with no overflow check. For large
   incoming amounts this wraps modulo `2^64`.

3. **`ceil_div` overflow.** `(a + b - 1)` can itself overflow for a wrapped-large `a`, silently
   shrinking the quotient.

4. **CLTV underflow.** `cltv_expiry - cltv_expiry_delta` (u32 − u16) wraps to a huge value when the
   recipient-supplied delta exceeds the incoming expiry.

5. **Denominator overflow — already fixed.** `(u64)1000000 + fee_proportional_millionths`. Before
   `96f026ecc` this was evaluated in 32 bits; choosing
   `fee_proportional_millionths = 2^32 − 1000000` (= `4293967296`) made the denominator `0`,
   producing a **divide-by-zero → SIGFPE → `lightningd` crash**. The backtrace in the fix commit
   confirms the crash path: `onion_decode → handle_blinded_forward → ceil_div`, reached from
   `peer_accepted_htlc` / `peer_got_revoke`.

### Reachability (why `--offline` is the mitigation)
The bug is exercised purely by inbound P2P traffic: a peer forwards an HTLC whose onion routes
through this node as a non-final blinded hop. No local RPC or operator action is required. The
attacker only needs to be able to get an HTLC admitted to one of the node's channels (e.g. open a
channel, or be reached via the public graph) and to control the recipient-side blinded-path data.
With `--offline` there are no peers and thus no inbound HTLCs, so the node is not exposed — which
matches the stated threat model exactly.

### Impact analysis (honest assessment)

* **Pre-fix (v26.06.6 base and earlier):** reliable remote crash of `lightningd` (SIGFPE). This is
  a denial-of-service against a routing/node operator, reproducible on demand because the malicious
  onion can be re-sent. The crash fires *after* the HTLC is irrevocably committed
  (`peer_accepted_htlc` runs at `RCVD_ADD_ACK_REVOCATION`), so it interrupts live payment
  processing.

* **Post-fix residual risk in this snapshot:** the denominator no longer reaches zero, so the
  specific crash is gone, but defects 1–4 remain. They yield a garbage `amt_to_forward` /
  `outgoing_cltv`. Today these are caught downstream. Verified that every `ONION_FORWARD` payload
  — including blinded forwards that carry only a `next_path_key` and no `short_channel_id` —
  funnels through the single checked `forward_htlc()` call at
  `lightningd/peer_htlcs.c:1299` (`htlc_accepted_hook_final`), so there is no forward path that
  skips validation:
  - `check_fwd_amount()` (`lightningd/peer_htlcs.c:334`) uses the overflow-checked
    `amount_msat_fee()`/`amount_msat_sub()` and enforces `amount_in − fee ≥ amt_to_forward`, so the
    node is never made to forward more than it received (a wrapped-large `amt_to_forward` →
    `fee_insufficient`; a wrapped-small one just forwards less, i.e. the node keeps the fee).
  - `check_cltv()` (`peer_htlcs.c:374`) plus `expiry_too_soon` (`:906`) and `expiry_too_far`
    (`:921`) reject the wrapped `outgoing_cltv`.
  The bundled test (`tests/test_pay.py::test_blinded_forward_policy`) confirms this: with
  `fee_proportional_millionths = 4293967296` the node forwards a nonsensical `234 msat` which the
  final node rejects (`final incorrect amount`), i.e. the payment fails rather than draining the
  intermediate node.

* **Why it is still a funds concern:**
  - It is unchecked, recipient-controlled arithmetic *inside* the amount that determines how much
    value leaves the node. The safety currently rests entirely on downstream checks being (and
    staying) correct and on every blinded forward funnelling through `forward_htlc`. Any future
    code path that consumes `payload->amt_to_forward` without re-validating it (e.g. a blinded
    forward that bypasses or relaxes `check_fwd_amount`, a plugin `htlc_accepted` override, or a
    different wrapped value that happens to land inside the fee/CLTV window) converts this into a
    direct over-forward / fee-skimming primitive.
  - The crash primitive is a component of compound attacks: a crash-loop keeps the node offline;
    while offline it cannot watch the chain, so a counterparty that holds a revoked commitment has
    a wider window to broadcast it and sweep outputs before the node can penalize. In that sense a
    P2P-triggered crash can be a *contributing cause* of funds loss, even though the arithmetic bug
    alone does not debit the balance.

### Recommendation
Do the computation with checked/saturating helpers and validate the recipient-supplied relay
parameters against the node's own policy *before* computing the forward amount:
- Reject (or clamp) if `fee_base_msat > amount_in` instead of letting the subtraction wrap.
- Use `amount_msat_sub` / `amount_msat_mul_div` (the overflow-checked helpers in `common/amount.c`)
  rather than raw `u64` arithmetic; e.g. mirror `amount_msat_sub_fee()` which already implements
  `out = 1000000*(in−base)/(1000000+ppm)` safely.
- Guard `cltv_expiry − cltv_expiry_delta` against underflow.
- Enforce that the decrypted `payment_relay` is consistent with the node's advertised fees and
  `cltv_expiry_delta` (the new `test_blinded_forward_policy` test asserts exactly this behaviour;
  make the check explicit at decode time rather than relying solely on the generic forward checks).

---

## Finding 2 — Splice `lowest_splice_amnt` accounting defects (present, unfixed)

### Location
`channeld/channeld.c`, `update_view_from_inflights()` (approx. lines 3723–3743). It is invoked on
the live P2P splice path when a new splice inflight is created (`channeld.c:4395`, `:4700`) and on
reestablish (`:6996`).

### Code under audit
```c
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

`struct inflight.amnt` (`channeld/inflight.h`) is "The new channel outpoint" amount, i.e. the
**absolute** new total funding of the inflight transaction. By contrast, `lowest_splice_amnt` is a
**relative** amount documented as "always negative or 0" (`channeld/full_channel.c:430,436`) and is
consumed as `amount_sat(-view->lowest_splice_amnt[side])` subtracted from the side's owed balance.

### The defects

1. **Absolute-vs-relative comparison (dead updates).** `splice_amnt` is the absolute new total
   (large, non-negative) but is compared against `lowest_splice_amnt[*][LOCAL]` (≤ 0). The test
   `absolute_total < (≤0)` is effectively always false, so the first two branches never run and
   `view[*].lowest_splice_amnt[LOCAL]` is never updated from the local splice amount. (The local
   splice delta is `inflight->splice_amnt`, which is what the comparison should evidently use.)

2. **Index confusion in the REMOTE view.** Branch 2 compares against
   `view[REMOTE].lowest_splice_amnt[REMOTE]` but writes to `...lowest_splice_amnt[LOCAL]`; branch 4
   compares against `view[REMOTE].lowest_splice_amnt[LOCAL]` but writes to
   `...lowest_splice_amnt[REMOTE]`. The two REMOTE-view minima are therefore maintained against the
   wrong entries.

### Why it matters for funds

`lowest_splice_amnt[side]` is the reserve accounting for pending splice-outs. `get_room_above_reserve()`
(`channeld/full_channel.c:418`) subtracts `-lowest_splice_amnt[side]` from `owed[side]` before
checking that a side keeps its reserve, and that function gates whether the channel will **add an
HTLC** (`full_channel.c:802`, `:839`, reached from the commitment-signed / update_add_htlc path). If
a pending splice-out by a side is under-tracked (the value stays `0` instead of going negative), the
node believes that side has more free balance than it will after the splice settles, and may commit
HTLCs that push the real post-splice balance below reserve — an over-commitment in a funds-critical
accounting path, driven by peer-negotiated splice amounts.

Related gap: the BOLT-mandated splice reserve check is **not implemented**. `check_balances()`
(`channeld/channeld.c:3680–3706`) carries an explicit `DTODO: Spec out reserve requirements for
splices!!` and does not enforce "if either side added a non-funding output, fail when that side's
balance < 1% of capacity". Combined with defect (1), splice-out reserve protection is effectively
absent.

### Confidence / exploit status
The code defects are concrete and verifiable by inspection. I have **not** constructed an
end-to-end scenario that turns them into a clean, direct balance debit; that would require a
specific splice + RBF + HTLC interleaving and is left as follow-up (a splice-aware fuzz/property
test is the right tool). Severity is therefore "funds-accounting integrity bug in a P2P path,
plausible over-commitment," not yet "demonstrated theft."

---

## Finding 3 — Splice tx signed with no balance validation at signing time / HSM blind-signs (present, unfixed)

### Location
- `channeld/channeld.c:resume_splice_negotiation()` (approx. lines 3770–3910): the splice
  transaction is finalized and signed here. Immediately before signing there is an explicit
  `DTODO` (line 3859): *"Validate splice tx takes none of our funds in either: 1) channel balance
  2) other side sneakily adding other outputs we own."*
- `hsmd/libhsmd.c:handle_sign_splice_tx()` (lines 1447–1479): the HSM request handler.

### The defect
`handle_sign_splice_tx` derives the local funding key and calls `sign_tx_input(...)` with
`SIGHASH_ALL` on whatever transaction it is handed. It performs **no validation at all**: it does
not check that the splice preserves the channel balance, that outputs pay only the expected
scripts, or that the peer has not attributed our funds to themselves. The HSM is CLN's intended
signing security boundary, yet for splice it is a blind signer.

That leaves `check_balances()` (called during the interactive-tx build at `channeld.c:4348`/`:4607`)
as the **only** place the splice economics are validated. `resume_splice_negotiation` re-signs the
stored `inflight->psbt` (e.g. on reconnect) without re-running that check, exactly the situation the
DTODO flags. Any path that lets a PSBT reach the HSM for splice signing without having first passed
`check_balances` in its final form would let a malicious peer have us sign a splice that moves our
funds.

### Confidence / exploit status
The validation-chain gap is verifiable by inspection (DTODO present + HSM does no checks). Whether a
concrete flow exists in which the PSBT signed here differs from the one `check_balances` approved
(e.g. via reconnect/RBF re-negotiation mutating the stored inflight PSBT) needs a targeted trace and
is left as follow-up. This is the same weak area as Finding 2: **the splice implementation is the
least-hardened funds path in the snapshot**, carrying multiple unimplemented/absent validations.

---

## Finding 4 — Mutual-close fee has no maximum bound; opener's whole balance can be burned to fees (present, unfixed)

### Location
- `closingd/closingd.c:receive_offer()` (approx. lines 245–382): receives the peer's
  `closing_signed` (fee + signature).
- `lightningd/closing_control.c:closing_fee_is_acceptable()` (lines 197–239): the master-side gate
  that decides whether the received close tx is stored as `channel->last_tx`.

### The defect
The close fee is subtracted from the **opener's** output (`closingd/closingd.c:73`). The received
fee is validated against a **minimum** only, in two places:
- `receive_offer` stores/relays the peer's offer if `received_fee >= min_fee_to_accept`
  (`closingd.c:376`). The computed `max_fee_to_accept` (from `calc_fee_bounds`) is used only to
  bound *our own* counter-offers (`init_feerange`/`adjust_offer`) and for display — it is never used
  to reject the *peer's* fee.
- `closing_fee_is_acceptable` (`closing_control.c:219`) rejects only fees *below*
  `feerate_min * weight`; there is no upper bound. On success it calls
  `channel_set_last_tx(channel, tx, &sig)`.

`channel->last_tx` is the mutual-close transaction that gets broadcast (our signature is re-derived
by the HSM at broadcast), so an accepted offer becomes spendable.

### Consequence
A malicious **closee** can send `closing_signed` with a fee up to the opener's entire balance
(`closingd.c:73` only fails if `fee > opener_balance`; `fee == opener_balance` passes and drops the
opener output as dust). With no maximum check, the opener node stores and can broadcast a close tx
that sends its **entire channel balance to miner fees**. The attacker gains nothing (funds are
destroyed, not redirected), so this is griefing-class — but it is a total loss of the opener's
funds and is P2P-reachable by the channel counterparty. `--offline` prevents it (no peer to send
`closing_signed`).

### Confidence / exploit status
The missing maximum bound is concrete and verifiable (both gates check only a floor). End-to-end
confirmation requires tracing that a non-converged high-fee offer survives as `last_tx` and is the
variant actually broadcast at `CLOSINGD_COMPLETE`; that final step is left as follow-up. Severity:
"opener's balance burnable to fees by a malicious counterparty (griefing), up to total loss."

---

## Secondary findings (same bug family, already fixed in this snapshot — listed for completeness)

These corroborate the attack surface (peer-controlled integers with missing bounds checks in P2P
daemons). All are crash/DoS class, not direct balance debits.

1. **`channeld` zero `next_commitment_number` on reestablish** — fixed by `eafdd9386`.
   A peer sending `channel_reestablish` with `next_commitment_number == 0` was not rejected in all
   states; now the channel is failed immediately (`channeld/channeld.c:5993`). DoS/protocol-state.

2. **`marginal_feerate()` u32 overflow** — fixed by `f2a0fb2c5` (`common/fee_states.c:166`).
   `current_feerate` is peer-influenced (`open_channel`/`update_fee`); `*1.1` as a double converted
   back to `u32` was UB. Now saturated in `u64`. Affects derived values such as `receivable_msat`.

3. **`funding_satoshis` above total Bitcoin supply** — fixed by `4b34ad332`
   (`openingd/common.c:max_channel_funding`). An absurd peer-supplied funding amount crashed
   `openingd` in libwally during commitment-tx construction. Now bounded at total supply. DoS.

4. **`connectd` websocket handshake header case-sensitivity** — `f0c702ed8`. Interop/DoS at the
   transport layer; no funds impact.

---

## Areas audited and found hardened (no exploitable funds bug identified)

To bound the search, the following funds-critical P2P paths were reviewed and found to have the
expected validation in place:

- **HTLC forwarding economics** — `lightningd/peer_htlcs.c:forward_htlc`/`check_fwd_amount` enforce
  `in ≥ fee + out` using the node's *own* channel feerate, so a peer/recipient cannot make the node
  forward more than it receives; CLTV enforced via `check_cltv` + `expiry_too_soon/far`. Final-node
  receipt enforces `hin->msat ≥ amt_to_forward` and matches `total_msat` against the invoice via
  `htlc_set_add`, so the preimage is not released for underpayment.
- **Commitment/revocation state machine** — `channeld/channeld.c` `handle_peer_commit_sig`
  verifies the peer's signature against the locally-built commitment and HTLC txs before acting;
  `handle_peer_revoke_and_ack` validates the revealed per-commitment secret against
  `old_remote_per_commit` and via `hsmd_validate_revocation`; revocation secret release
  (`send_revocation` → `make_revocation_msg`) happens only after the new commitment is persisted to
  the master and uses index `next_index[LOCAL]-2`, i.e. the already-superseded state.
- **Reestablish / data-loss-protect** — `peer_reconnect` + `check_current_dataloss_fields` /
  `check_future_dataloss_fields` cross-check commitment/revocation numbers and per-commitment
  secrets, including the new zero-commitment-number rejection.
- **`update_fee` / `update_blockheight`** — sender-must-be-opener, range checks
  (`feerate_same_or_better`) and affordability (`channel_update_feerate`) enforced.
- **Mutual close (amounts/signature)** — `closingd/closingd.c` rebuilds the close tx locally from
  the locally-known balances and only accepts a peer signature that validates against the
  locally-constructed (or correctly trimmed) transaction, so the peer cannot spoof the output
  amounts. (The *fee* itself, however, has no maximum bound — see Finding 4.)
- **Onion messages** — `common/onion_message_parse.c` bounds-checks the hop payload
  (`fromwire_bigsize` length + `maxlen > max` + TLV cursor) and enforces the single-TLV rule for
  forwarding; onion messages carry no funds, so this is a DoS-only surface and no funds bug applies.
- **Splice / dual-funding PSBT** — `channeld/channeld.c:check_balances` and
  `openingd/dualopend.c` enforce per-side input ≥ output + splice amount + minimum fee, reject a
  side splicing out more than its attributable channel funds, and enforce serial-id parity /
  duplicates. Signing is gated behind these checks.
- **Onchain resolution / justice** — `onchaind/onchaind.c` `handle_their_cheat` uses the shachain
  revocation preimage to penalize all revoked outputs (`steal_to_them_output`, `steal_htlc`);
  our/their unilateral and HTLC resolution paths match scripts/CLTVs and propose spends. HTLC
  deadlines and the "abandon incoming" heuristic in `peer_htlcs.c` follow BOLT #2 step logic.
- **HSM signing policy** — `hsmd/libhsmd.c` derives keys per channel/commitment and sanity-checks
  tx shape before signing; commitment/HTLC/penalty/close signing are scoped to the expected
  funding wscript and keys. (CLN's documented design relies on `channeld` for semantic validation;
  the standing `FIXME`s about deeper HSM checks remain, but no peer-reachable bypass was found.)
- **Amount/fee helpers** — `common/amount.c` add/sub/mul_div/fee helpers are overflow-checked and
  return success flags; `amount_tx_fee` asserts against overflow.

---

## Caveats

- **Provenance verified.** `origin` = `https://github.com/ElementsProject/lightning`; local
  `master` (`c1551c557`) and `v26.06.6` (`fcb573e`) match upstream `git ls-remote` exactly, and the
  working tree is clean. There is **no locally planted modification**; the findings concern genuine
  upstream code. The `where-the-500-went` and `variant-pyunittests` tags point at a disconnected,
  pre-history relic (no merge-base with `master`, ancient "anchor"-scheme commits) and are not part
  of the audited code.
- This is a static, manual review of one snapshot; it is not a proof of absence. A dynamic/fuzz
  campaign against the blinded-forward decode path (the `smite`-style fuzzing that found the
  neighbouring bugs) is the natural next step and is likely to surface siblings of the primary
  finding.
- The primary finding is presented with its true impact class. The reliable primitive in this
  snapshot is a remote crash / payment disruption; direct balance loss requires either an earlier
  (pre-fix) build for the divide-by-zero crash, or an additional defect that consumes
  `payload->amt_to_forward` without the current downstream re-validation. If the task's premise is
  a strict "peer can directly drain balance," the candidate surface to keep probing is any new
  blinded-forward / `htlc_accepted` code path that skips `forward_htlc`'s checks.
