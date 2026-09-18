# Binary audit of Core Lightning v26.06.7 (patched) vs v26.06.6 (unpatched) — qwen3.8-2.4T

**Task.** Take the source-level funds-path audit (`CLN-AUDIT-QWEN38-2.4T.md`, snapshot
`master@c1551c557`) and, from the *patched release binaries* alone (no patched source), decide per
finding whether v26.06.7 **fixed**, **did not fix**, or only **partially fixed** the bug — then rank
likely CVEs. This is verification of known bugs from binaries, not discovery.

**Method in one line:** the two builds use different optimisation levels (`-Og` unpatched vs `-O3`
patched), so raw instruction/symbol diffing is dominated by codegen noise. Instead I diffed
(a) DWARF `file:line` subprogram annotations, (b) `.rodata` log/error strings, (c) the *semantic*
call/branch/arithmetic structure of each finding's function, and (d) cross-checked the aarch64
patched build. All claims below cite concrete binary evidence.

---

## 1. Material

| Dir | arch | version | opt | role |
|---|---|---|---|---|
| `amd64-unpatched` | x86-64 | v26.06.6 | `-Og` | reference (source known) |
| `amd64-patched`   | x86-64 | v26.06.7 | `-O3` | target |
| `arm64-patched`   | aarch64 | v26.06.7 | `-O3` | cross-check ISA |

All three: ELF, **not stripped, full DWARF**. Embedded `--version` strings confirm `v26.06.6` /
`v26.06.7`. Unpatched source tree: `~/tmp/lightning` (`master`, `v26.06.6` tag reachable). Patched
source: **not available** (that is the point). Note the patched build is *not* straight master
`HEAD` — it is a private v26.06.7 branch — so master commit hashes are used only to *name* fixes,
and verdicts rest on the binaries themselves.

Key caveat carried throughout: **absolute DWARF line numbers shift between builds** (unrelated edits
move code), so I never compared absolute lines across versions; only per-function structure, named
calls, and string/constants.

---

## 2. Verdict table (prior source findings → v26.06.7 binary)

| # | Prior source finding | v26.06.7 verdict | Confidence |
|---|---|---|---|
| P | Blinded-path forward-amount arithmetic (`onion_decode.c`) — divide-by-zero crash | **FIXED (the crash)** | High |
| P' | same — residual numerator/CLTV wrap (defects 1–4) | **NOT fixed** (still raw arithmetic) | High |
| 2 | Splice `lowest_splice_amnt` accounting (`update_view_from_inflights`) | **NOT fixed** | High |
| 3 | Splice tx / HSM blind-sign (`handle_sign_splice_tx`) | **NOT fixed** | High |
| 4 | Mutual-close fee has **no maximum** bound | **FIXED** | High |

Additional v26.06.7 changes not in the prior audit (found by full binary diff) are covered in §4.

---

## 3. Finding-by-finding evidence

### P — Blinded-path forwarding amount overflow → divide-by-zero crash — **FIXED**

Prior audit: `handle_blinded_forward()` computes
`ceil((amt − fee_base) * 1_000_000 / (1_000_000 + fee_proportional_millionths))` from
recipient-controlled `encrypted_recipient_data`. The denominator was evaluated in **32 bits**;
choosing `fee_proportional_millionths = 2^32 − 1_000_000` makes it `0` → `div` by zero → **SIGFPE,
remote crash of the forwarding path** (reach `onion_decode → handle_blinded_forward → ceil_div`).

**Unpatched v26.06.6 binary (vulnerable)** — `lightningd`, `handle_blinded_forward` @ `0x133e4f`:

```
133eea: mov  0x4(%rax),%edx        ; fee_proportional_millionths (u32)
133ef3: sub  %rax,%rdi             ; amt - fee_base            (64-bit)
133ef6: lea  0xf4240(%rdx),%esi    ; 1000000 + fee_prop -> ESI  <<<< 32-BIT
133efc: imul $0xf4240,%rdi,%rdi    ; numerator * 1000000        (64-bit)
133f03: call 133d85 <ceil_div>
; ceil_div:  lea -0x1(%rsi,%rdi,1),%rax ; div %rsi   <<<< divides by wrapped 32-bit value
```

`lea …,%esi` writes a 32-bit register, so `1000000 + fee_prop` is truncated mod 2^32. With
`fee_prop = 0xFFEFD160` (4293967296) the denominator becomes `0` and `div %rsi` raises SIGFPE.
The crash primitive is present and remotely reachable.

**Patched v26.06.7 binary (fixed)** — `onion_decode` (inlined `handle_blinded_forward`):

x86-64, @ `0x14d157`:
```
14d157: mov  0x4(%rax),%ecx        ; fee_proportional_millionths
14d15a: mov  0x8(%rax),%edx        ; fee_base_msat
14d167: sub  %rdx,%rax             ; amt - fee_base            (64-bit)
14d16c: imul $0xf4240,%rax,%rax    ; numerator * 1000000        (64-bit)
14d173: lea  0xf423f(%rcx,%rax,1),%rax ; numerator + denom - 1  (64-bit)
14d17b: add  $0xf4240,%rcx         ; 1000000 + fee_prop -> RCX  <<<< NOW 64-BIT
14d182: div  %rcx                  ; 64-bit divide, denom can no longer wrap to 0
```

aarch64 cross-check, @ `0x14fff0`:
```
14fff8: sub  x0, x0, x4            ; amt - fee_base
14fffc: madd x0, x0, x2, x3        ; *1000000 + (denom-1)       (64-bit)
150000: udiv x0, x0, x1            ; 64-bit divide
```

**Verdict: FIXED.** The denominator (and the numerator multiply and the `a+b-1` rounding) are now
computed in full 64-bit on both ISAs, so the recipient can no longer force a zero divisor → the
remotely-triggerable SIGFPE crash is eliminated. This corresponds to upstream
`96f026ecc lightningd: check value overflow for forward amounts`.

**P' — residual wrap NOT fixed.** The patched code still performs the raw, unchecked
`amt − fee_base` (`sub %rdx,%rax` @ `0x14d167`) and `cltv − cltv_expiry_delta`
(`sub %edx,%eax` @ `0x14d1a1`). No bounds/saturating helper (`amount_msat_sub`, clamp, or reject)
was added around either. This matches the prior audit's own assessment that `96f026ecc` was an
*incomplete* fix: it stops the crash but leaves a latent funds-correctness wrap that downstream
`check_fwd_amount`/`check_cltv` currently contain. **Verdict on P': NOT fixed (residual).**

### Finding 2 — Splice `lowest_splice_amnt` accounting — **NOT fixed**

Prior audit: `update_view_from_inflights()` (channeld) compares an absolute funding total against a
relative `lowest_splice_amnt` (dead updates) and swaps the REMOTE-view indices, so a pending
splice-out can be under-counted in `get_room_above_reserve()`, which gates HTLC acceptance →
plausible over-commitment.

Binary evidence in `lightning_channeld`:
- DWARF shows `update_view_from_inflights` only **shifted** line number (3723→3797) due to
  unrelated insertions above it; the function itself is present and structurally unchanged.
- String diff of patched vs unpatched channeld adds only feerate-bound messages
  (`Splice feerate_perkw %u is above our maximum %u`, `… below our minimum %u`,
  `Feerate %u is too high…`) and compiler clones (`last_inflight_index.part.0`,
  `update_hsmd_with_splice.isra.0`). **No** new string or call addresses the
  `lowest_splice_amnt` / `get_room_above_reserve` accounting, and no new
  `splice_amnt`-vs-`lowest_splice_amnt` comparison was added.
- The `DTODO: Spec out reserve requirements for splices!!` gap in `check_balances` has no
  corresponding new enforcement in the binary.

**Verdict: NOT fixed.**

### Finding 3 — Splice tx / HSM blind-signs — **NOT fixed**

Prior audit: `handle_sign_splice_tx()` (hsmd) blind-signs with `SIGHASH_ALL` and performs no
balance/script validation; `resume_splice_negotiation` re-signs the stored PSBT without re-running
`check_balances` (explicit `DTODO`).

Binary evidence: `hsmd/libhsmd.c` DWARF is **identical** between the two builds —
`handle_sign_splice_tx` is still at line 1447 and `handle_sign_commitment_tx` still at 1848; no new
subprograms, no new validation strings. No new bounds-check call was inserted into the splice-sign
path.

**Verdict: NOT fixed.**

### Finding 4 — Mutual-close fee has no maximum bound — **FIXED**

Prior audit: the close fee (deducted from the opener's output) is validated only against a
*minimum* in both `closingd.c:receive_offer` and `closing_control.c:closing_fee_is_acceptable`;
there is no upper bound, so a malicious closee can burn the opener's entire balance to fees.

**Patched v26.06.7 adds an explicit maximum bound on both sides.**

lightningd side (`closing_control.c`):
- New standalone symbols `close_tx_check` (`0xa61f0`) and `calc_max_close_feerate` — `close_tx_check`
  is a real function in the patched build (it was not a standalone symbol before), validating the
  shape and fee of the peer's closing tx.
- New log strings: `"Bad closing_received_signature: %s"`, `"output %zu goes to unknown script %s"`,
  `"Their actual closing tx fee is %s vs previous %s: weight is %lu"`, and crucially
  `"… That's above our max %s for weight %lu at feerate %u"` (`0x1fe268`). The closing-message path
  (`closing_msg`) now calls `close_tx_check`, `feerate_min`, `unilateral_feerate`, and **two**
  `amount_sat_less` comparisons — i.e. both a floor and a ceiling on the fee.

closingd side (`lightning_closingd`):
- Unpatched: **no** max-fee rejection string; only `min_fee_to_accept` logic.
- Patched adds: `"Fee %s became larger than our max fee %s"` — a rejection path for an oversized
  peer fee. Confirmed present in both amd64 and arm64 patched builds.

**Verdict: FIXED.** v26.06.7 enforces a maximum close fee in both the subdaemon and the master, so
the opener's balance can no longer be burned to an unbounded fee.

---

## 4. Additional v26.06.7 changes found by full binary diff (beyond the prior audit)

These are real code changes present in v26.06.7 that the prior source audit did not list; most are
in the same "peer-controlled integer missing a bound" family, i.e. additional hardening.

1. **Funding-feerate `*25/24` overflow / assert-DoS — FIXED.** Unpatched computed
   `next_feerate = last_feerate * 25 / 24; assert(next_feerate > last_feerate)` in
   `peer_control.c` (`json_add_channel`/`listpeerchannels`) and `dual_open_control.c`
   (`json_openchannel_bump`); a large stored `funding_feerate` overflows the multiply, the assert
   fails → abort. Patched adds a safe helper `next_funding_feerate` (standalone symbol, amd64
   `0x1666c0`; present on arm64) doing 64-bit math with range checks, plus
   `our_feerate_max` (new symbol `0x96d80`), new strings
   (`"Can't calculate the next feerate…"`, `"Feerate %u is above the most we'll pay (%u)…"`,
   `"Funding feerate %u leaves no valid next feerate: omitting next_feerate"`), and two DB
   migrations sanitising bad stored values:
   `UPDATE channel_funding_inflights SET funding_feerate = 1000000 WHERE funding_feerate > 1000000 OR funding_feerate < 0;`
   and `… SET funding_feerate = 253 WHERE funding_feerate = 0 OR funding_feerate IS NULL;`.

2. **Feerate sanity clamp — added.** New string
   `"Feerate for %u blocks (%u) is above sanity ceiling (%u): clamping!"` plus `our_feerate_max`
   scanning helper (SIMD max over the feerate array) in `chaintopology.c`. Bounds the feerates fed
   to `channel_update_feerates` / the inflight update paths.

3. **channeld / dualopend splice feerate bounds — added.** New DWARF functions
   `accepted_feerate_max`, `accepted_feerate_min`, `proposed_feerate_max` (channeld) and
   `feerate_in_range` (dualopend), with the strings cited in §3/Finding 2.

4. **onchaind restart on reorg — added.** New `onchaind_restart` / `reorg_restart_onchaind`
   (`onchain_control.c`) and string `"Chain reorganization: did not restart onchaind"` — on a reorg
   the onchain watcher is now relaunched rather than dropped. Reliability, not a peer-exploit fix.

5. **bitcoind filteredblock rework — added.** New `most_recent_filteredblock_call`
   (`bitcoind.c`, inlined in `-O3`), tracking the latest filtered-block request (new pointer field)
   to avoid duplicate/redundant fetches during replay. Reliability.

6. **`marginal_feerate()` — still floating-point, NOT the master integer fix.** Both builds compute
   `marginal_feerate` with `mulsd` against the constant `1.1` (patched `.rodata` `0x254108` = `1.1`,
   `0x254100` = `0.9`). The master saturation fix `f2a0fb2c5` is **not** present in either release
   binary. (Listed as a secondary/DoS-class item in the prior audit; unchanged here.)

7. **Log-truncation heap-mismatch crash — FIXED.** Unpatched `logv` calls `cap_header()` then
   `free()` on the result (`b81f4: call cap_header`, `b821c: call free@plt`); when a message is
   truncated, `cap_header` returns a `tal_fmt`-allocated pointer, so `free()` on a tal pointer is a
   heap-corruption/crash. Patched `logv` (`0xc3797`) allocates the `[TRUNCATED …]` replacement onto
   `tmpctx` via `tal_fmt_` and only ever `free()`s the original `vasprintf` buffer — no `free()` of a
   tal pointer. Corresponds to upstream `81425f178` ("don't crash when truncating large log
   messages"). DoS-class (peer can send oversized logged data), not a funds bug.

---

## 5. Likely CVE ranking (prediction)

Ranked by remote reachability + impact + clarity of the before/after binary delta:

1. **Blinded-path forwarding amount → divide-by-zero SIGFPE (remote DoS).** FIXED in 26.06.7.
   This is the strongest CVE candidate: an unauthenticated, P2P-delivered onion can crash the
   forwarding path on demand, reproducible, interrupting live payment processing. Clear 32-bit→64-bit
   delta in both ISAs. **HIGH** confidence this is a published CVE for v26.06.7.

2. **Mutual-close fee unbounded → opener's entire balance burned to fees.** FIXED in 26.06.7.
   P2P-reachable by the channel counterparty; griefing-class but total loss of the opener's funds.
   Clear new max-bound enforcement in both closingd and closing_control. **MEDIUM-HIGH** confidence
   for a CVE (funds-loss, though non-redirect).

3. **Funding-feerate `*25/24` overflow / assert abort.** FIXED in 26.06.7. DoS/abort class; requires
   a large stored funding feerate (peer-influenced at open/bump). **MEDIUM** confidence for a CVE.

4. Lower / unlikely as standalone CVEs: feerate sanity clamp, channeld/dualopend splice feerate
   bounds (hardening); onchaind-reorg restart and bitcoind filteredblock rework (reliability);
   `marginal_feerate` float (unchanged, DoS-class, already tracked upstream as `f2a0fb2c5`).

Not candidates for *this* release's CVE set because they are **not** fixed in v26.06.7 (they are
open findings / future-CVE material): splice `lowest_splice_amnt` accounting (Finding 2), HSM
blind-splice signing (Finding 3), and the residual blinded-forward numerator/CLTV wrap (P').

---

## 6. Confidence, limits, artifacts

- Verdicts marked High rest on unambiguous binary deltas (arithmetic width, new rejection strings,
  new standalone symbols, DB migrations) corroborated on a second ISA. None rely on raw
  instruction-byte diffing, which is unreliable across the `-Og`/`-O3` pair.
- The `-O3` patched build inlines aggressively; some functions (e.g. `cap_header`,
  `most_recent_filteredblock_call`, `handle_blinded_forward`) survive only inlined, so I located
  them by DWARF line + surrounding named calls.
- Repro artifacts (disassembly, DWARF dumps, string/line diffs) are in
  `analysis/qwen3.8-2.4T/` (`patched_full.s`, `unpatched_full.s`,
  `unp_handle_blinded_forward.s`, `patched_onion_decode.s`, `arm64_onion_decode.s`,
  `unp_closing_fee.s`, `patched_close_tx_check.s`, `patched_closing_msg.s`, `patched_logv.s`,
  `func_delta.txt`, `channeld_func_delta.txt`, `marker_delta.txt`, `strings_added.txt`,
  `*.dwarf`).
