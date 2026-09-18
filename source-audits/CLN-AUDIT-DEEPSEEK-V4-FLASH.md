# CLN Peer-to-Peer Security Audit — DeepSeek v4 Flash

> **Reviewer's note (GLM-5.3-Flash, Z.ai):** The audit below was produced by DeepSeek v4 Flash (0731 checkpoint). I independently verified every code citation against commit `c1551c557`: F1's state-machine and fee-affordability mechanics, F2's assert path, F3's overflow containment, and F4's missing checks all check out code-accurately. Caveats: F1 is a *documented, deliberate* tradeoff (see `full_channel.c:549-573`, lightning-rfc #728/#740), not an unnoticed bug; the `max_htlc_value_in_flight` cap suggestion does not fix F1; and the audit's biggest gap is the unexamined peer-reachable assert surface — especially the splice paths (channeld.c:1749, 4035, 4538-4927) — plus complete silence on quiescence (STFU) and the blinded-path CLTV underflow at onion_decode.c:123. Severity ratings are broadly sound.

**Target:** Core Lightning (CLN), commit `c1551c557` (master, ~2026-08-26, post `v26.06.6`)
**Scope:** Peer-to-peer (`--offline` immune) code paths that can **lose funds**.
**Method:** Static audit of the channel/commitment state machine, HTLC/forwarding paths,
blinded routing, dual-funding/splice/reestablish, and the (new, experimental)
`option_simple_close` protocol. Key files: `channeld/`, `openingd/`, `closingd/`,
`lightningd/{peer_htlcs,peer_control,dual_open_control,simple_close_control}.c`,
`common/{full_channel logic, amount, onion_decode, htlc_trim, htlc_tx}.c`.

Severity scale: **CRITICAL** (unconditional/cheap fund theft) → **HIGH** (fund theft with
conditions) → **MEDIUM** (availability / channel freeze that can strand funds) →
**LOW** (theoretical).

---

## F1 — HIGH — Commitment-fee theft: a malicious *fundee* can drain the *funder*'s balance by inflating the commitment weight with dust-sized HTLCs

This is the primary finding and matches the "peer-to-peer, offline-safe, loss of funds"
profile exactly.

### Location

- `channeld/full_channel.c` — `add_htlc()` affordability checks, **lines 785–882**.
- `common/initial_commit_tx.c` — `try_subtract_fee()`, **lines 31–48**.
- `channeld/commit_tx.c` — **line 195** (return value of `try_subtract_fee` ignored).
- `lightningd/opening_common.c` — **line 150** (`max_htlc_value_in_flight = AMOUNT_MSAT(UINT64_MAX)`).

### The bug

The commitment fee is always paid out of the **opener/funder**'s direct output
(`try_subtract_fee(opener, …)`, `commit_tx.c:195`). The check that the funder can afford
the fee only runs **when the sender of the HTLC is the funder**:

```c
/* full_channel.c:818 */
if (channel->opener == sender) {                     /* only when sender IS the funder */
    if (amount_msat_less_sat(remainder, fee)) {      /* funder affordability  */
        ...
        return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;
    }
    ...
}
/* full_channel.c:838 */
if (sender == LOCAL) {                               /* only when *we* add */
    /* checks both our own and the peer's commitment fees */
    ...
}
```

When the **fundee** (`sender == REMOTE`) adds an HTLC on a channel **we** funded
(`opener == LOCAL`):

- only `get_room_above_reserve(…, sender=REMOTE, …)` (full_channel.c:802) is run — it checks
  the *fundee*'s balance above the *fundee*'s reserve, **not** the funder's ability to pay
  the resulting commitment fee;
- `channel->opener == sender` (818) is false → the funder-fee check is **skipped**;
- `sender == LOCAL` (838) is false → the both-sides fee checks are **skipped**.

The size of the on-chain commitment fee grows with the number of untrimmed HTLC outputs
(`commit_tx_num_untrimmed` + `commit_tx_base_fee`, `commit_tx.c:160–195`; ≈ +172
weight-units per additional HTLC). The only aggregate caps the fundee must satisfy are:

- `max_accepted_htlcs` (483, our own announced config);
- `max_htlc_value_in_flight`, which **we announce as `UINT64_MAX`**
  (`opening_common.c:150`), i.e. **no value cap at all**.

So a fundee can add up to **483 just-above-dust HTLCs** (~1'000 msat each, above
`dust_limit + htlc_success_fee`) without tripping *any* funder-affordability check.

At commitment construction, if the fee now exceeds the funder's balance,
`try_subtract_fee()` clamps the funder output to **0**:

```c
/* initial_commit_tx.c:43-47 */
if (amount_msat_deduct_sat(opener_amount, base_fee))
    return true;
*opener_amount = AMOUNT_MSAT(0);   /* funder balance silently wiped */
return false;
```

and `commit_tx.c:195` **ignores the `false` return**, so a valid commitment is built and
**signed** with *no `to_local` output at all* (`commit_tx.c:278` requires `self_pay >=
dust_limit` to add the output; 0 sat → omitted). We then send `revoke_and_ack`,
irrevocably handing the peer a signature on that commitment.

### Exploit scenario

1. Victim (funder, `opener == LOCAL`) opens a channel with the attacker; attacker obtains
   a large balance (via `push_msat`, a payment, or a service the attacker sells). Victim's
   remaining balance is below `483 × 172 × feerate_per_kw / 1000` sats (e.g. ~210k sat at a
   feerate of 2530; more at higher feerates).
2. Attacker (fundee) sends `update_add_htlc` × N (up to 483, each just above the trim
   threshold). Every one passes `add_htlc` (attacker's balance covers the HTLC amounts,
   count ≤ 483, value unlimited).
3. Attacker sends `commitment_signed`. The commitment now carries ~N extra HTLC outputs;
   the fee exceeds the victim's balance. `try_subtract_fee` zeroes the victim's `to_local`.
   Victim validates the (matching) signature and sends `revoke_and_ack`, revoking its old,
   fair commitment.
4. Attacker broadcasts the commitment. The victim's entire balance is paid to miners as
   transaction fees; the victim recovers nothing. The attacker's own HTLCs (payments to the
   victim with unknown preimages) time out back to the attacker — a **net theft of the
   victim's channel balance** at essentially zero cost to the attacker beyond temporary
   fund lockup.

`--offline` nodes are safe: the attack requires a live, connected peer (`update_add_htlc`,
`commitment_signed`, `revoke_and_ack`).

### Related asymmetry (DoS direction)

The same affordability gap, in the other direction, is guarded by a **crash** rather than a
graceful rejection: `channeld/channeld.c:2104–2112`

```c
if (peer->channel->opener == REMOTE) {          /* peer is funder */
    assert(can_opener_afford_feerate(peer->channel,
                                     channel_feerate(peer->channel, LOCAL)));
}
```

A malicious **funder** can send `update_fee(F1)` (checked for affordability at the *old*
HTLC set, `channel_update_feerate` → `can_opener_afford_feerate`, full_channel.c:1432),
then one small `update_add_htlc` (its `add_htlc` checks still run at the *old, uncommitted*
feerate because `RCVD_ADD_HTLC` is not yet `HTLC_LOCAL_F_COMMITTED`, htlc_state.c:90), then
`commitment_signed`. The fee state advances to `RCVD_ADD_COMMIT` (now committed), and the
assert re-checks affordability at `F1` *with the extra HTLC* → **SIGABRT / channeld crash**.
On reconnect the peer replays the same three messages → permanent channel freeze /
forced unilateral close (griefing). Note the *local* funder direction has **no** assert and
no check at all — which is exactly F1.

### Suggested hardening

- In `add_htlc`, run the funder-affordability and fee-headroom checks regardless of
  `sender` (compute `fee_for_htlcs` on the funder's commitment and require
  `funder_balance − htlc ≥ funder_reserve + fee + 660-anchors + marginal_feerate headroom`).
- Reject instead of `assert` in `handle_peer_commit_sig` (`peer_failed_warn` + fail
  channel), and cap accepted in-flight HTLC *value* (do not announce
  `max_htlc_value_in_flight = UINT64_MAX`).

---

## F2 — MEDIUM — `channeld` abort (SIGABRT) reachable by a malicious funder → channel freeze / forced close (availability, funds at risk while frozen)

Covered in F1's "related asymmetry". The assert at `channeld/channeld.c:2109` is the *only*
guard that the funder can afford the feerate once a commitment with additional HTLCs is
constructed, and it only runs when the peer is the funder. Because the pre-commit checks
run at a stale feerate, the assert is reachable with a protocol-conforming
`update_fee → update_add_htlc → commitment_signed` sequence. `lightningd` responds to the
subdaemon's death by force-closing the channel (`lightningd/subd.c:627–658`, `channel_errmsg`),
so the impact is a repeatable channel-freeze/griefing DoS. Not direct theft (the last
*committed* state is fair), but the forced close can strand in-flight HTLCs near CLTV
deadlines.

---

## F3 — LOW (availability) — Integer overflow still present in blinded-path forward amount

`common/onion_decode.c:119–122`

```c
u64 amt = amount_in.millisatoshis; /* Raw: allowed to wrap */
p->amt_to_forward = amount_msat(ceil_div((amt - enc->payment_relay->fee_base_msat) * 1000000,
                                         (u64)1000000 + enc->payment_relay->fee_proportional_millionths));
```

The recent fix (`96f026ecc`, "lightningd: check value overflow for forward amounts")
only cast the denominator to `u64` to close the **division-by-zero** (DoS, SIGFPE). The
numerator `(amt − fee_base_msat) * 1000000` still **overflows `u64`** for any blinded-path
HTLC ≳ 180'000 BTC of msat (`2^64 / 1e6`), and `amt − fee_base_msat` can **underflow** when
`fee_base_msat > amt` (both are attacker-controlled from `encrypted_recipient_data`). The
resulting `amt_to_forward` is garbage. This is **bounded** for fund-loss purposes: it flows
into `forward_htlc` → `check_fwd_amount` (`lightningd/peer_htlcs.c:856`), which requires
`amt_to_forward <= amt_in − fee`, so a wrapped value larger than what we received is
rejected and nothing extra is ever paid out. Impact is limited to mis-forwarded/failed
payments (availability) for huge/underflowing amounts. Should still be fixed with a checked
`mul`/`sub` (e.g. reject on overflow), since `(u64)1000000 + ppm` itself only addresses
the crash.

---

## F4 — LOW/MEDIUM (conditional fund loss) — Funding-outpoint reuse protection is incomplete

The v26.06.6 security fix "reject a channel that reuses an existing funding outpoint"
(`ce022d8c5`, in `lightningd/opening_control.c:539`) is **partial**:

```c
/* opening_control.c:536-543 — only the v1 fundee path */
if (find_channel_by_funding_outpoint(uc->peer, &funding)) {
    force_peer_disconnect(ld, uc->peer, "Funding outpoint already in use");
    return;
}
```

```c
/* lightningd/channel.c:882-892 — compares only the channel's CURRENT funding */
struct channel *find_channel_by_funding_outpoint(const struct peer *peer,
                                                 const struct bitcoin_outpoint *outpoint)
{
    list_for_each(&peer->channels, c, list)
        if (bitcoin_outpoint_eq(&c->funding, outpoint))
            return c;
    return NULL;
}
```

Gaps:

1. Only the **v1 fundee** path is checked. The **v2 / dual-funding** path
   (`dual_open_control.c` `wallet_update_channel`/`wallet_commit_channel`) has no
   equivalent check.
2. **Older RBF inflights** are never checked: `channel->funding` tracks the *latest*
   inflight, so a v1 `funding_created` can reference an older (still mineable) inflight's
   outpoint of a v2 channel and bypass the check.
3. In-flight/committed channels opened *concurrently* are only checked at the moment of
   `OPENING_FUNDEE_REPLY`; nothing re-validates later.

If two channels end up funded by the **same on-chain output** (one channel's commitment
spends it with the other channel's 2-of-2 keys), the losing channel's commitment is invalid
and its balance is unrecoverable — conditional on the attacker controlling a dual-funded
channel + an older inflight + mining the specific tx. Worth fixing comprehensively
(check all inflights, add a v2-side check, and enforce a DB-level uniqueness constraint on
`funding_tx_id`).

---

## Areas audited and found sound (no fund-loss path found)

- **Commitment construction** (`channeld/commit_tx.c`, `common/htlc_tx.c`,
  `common/htlc_trim.c`): fee always deducted from the opener's output; the fundee's
  `to_local` cannot be touched by feerate; trimming uses the same predicate on both sides
  and any disagreement fails signature validation.
- **`commitment_signed` / `revoke_and_ack` / reestablish** (`channeld/channeld.c`):
  `htlc_sigs` count, commitment numbers, per-commitment points and the revocation chain are
  all signature/HSM-bound; the recent zero-`next_commitment_number` and data-loss-protection
  checks are present.
- **HTLC forwarding / MPP / blinded terminal** (`lightningd/peer_htlcs.c`,
  `lightningd/htlc_set.c`): `check_fwd_amount`, CLTV checks, `amount_msat_mul_div` overflow
  handling and MPP `so_far` accounting prevent paying out more than received.
- **`option_simple_close`** (`closingd/simpleclosed.c`, `common/close_tx.c`,
  `lightningd/simple_close_control.c`): the closee always builds the tx from *its own*
  balances (`closee_amount = local_sat`, `closer_amount = funding − local_sat − fee`,
  rejected if fee > closer balance in all non-OP_RETURN variants); the closee cannot be made
  to sign a tx paying it less or the attacker more. Dust-limit and variant-selection logic
  use each side's own dust limit. Locktime is echoed/validated. (Minuscule msat rounding is
  inherent to BOLT.)
- **Legacy `closingd`**: funder pays fee, affordability is checked; the "trimmed"
  fallback only ever omits the *peer's* own output; `fee_range` quickclose keeps the
  agreed fee inside our acceptable range.
- **Opening validation** (`openingd/common.c`, `openingd/openingd.c`): funding bounds
  (incl. the recent `max_supply` fix), reserves, dust-vs-reserve, to_self_delay, htlc limits,
  and the "all-dust commitment" check are enforced.

---

## Summary

| # | Severity | Area | Impact |
|---|----------|------|--------|
| F1 | HIGH | `channeld/full_channel.c` `add_htlc` (fee-affordability skipped for fundee-added HTLCs) + `max_htlc_value_in_flight = UINT64_MAX` | Malicious **fundee drains funder's balance** to commitment fees (loss of funds, p2p-only) |
| F2 | MEDIUM | `channeld/channeld.c:2109` `assert(can_opener_afford_feerate())` | Malicious funder aborts `channeld` → channel freeze / forced close (availability) |
| F3 | LOW | `common/onion_decode.c:121` | Blinded-path forward amount `u64` overflow (wrong forward amounts / payment failures) |
| F4 | LOW/MED | `lightningd/opening_control.c:539` / `lightningd/channel.c:882` | Funding-outpoint reuse check incomplete (v2 path + RBF inflights) → possible duplicate-funding fund loss |

Primary recommendation: fix F1 first — enforce funder fee-affordability (including
`marginal_feerate` headroom) on *every* `add_htlc` regardless of sender, and stop
announcing an unbounded `max_htlc_value_in_flight`.
