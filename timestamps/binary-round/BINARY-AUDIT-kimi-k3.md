# CLN v26.06.7 Patched-Binary Audit — kimi-k3

**Target:** `binary/amd64-unpatched` (v26.06.6, x86-64) vs `binary/amd64-patched` (v26.06.7, x86-64), with parity spot-checks on `binary/arm64-patched` (v26.06.7, aarch64).
**Reference source:** `~/tmp/lightning` (unpatched master tree).
**Date:** 2026-08-31.

---

## 0. Executive summary

| # | Bug (from `../CLN-AUDIT-KIMI-K3.md`) | Severity | Verdict in v26.06.7 | Confidence |
|---|--------------------------------------|----------|---------------------|------------|
| 1 | closingd: unbounded mutual-close fee → burn 100 % of funder balance | Critical | **FIXED** (3 layers: closingd send_offer max-fee guard; lightningd `closing_fee_is_acceptable` max bound via new `calc_max_close_feerate()`; new `close_tx_check()` shape validation) | Very high |
| 2 | channeld: `check_tx_abort` checks `inflight` instead of `itr` | High | **FIXED** (checks the current inflight + `i_sent_sigs` flag) | Very high |
| 3 | dualopend/lightningd: RBF after funding mined clobbers mined inflight | High | **NOT FIXED** (all gates identical; only a new defense-in-depth onchain watch, `channel_watch_inflight_outs`) | Very high |
| 4 | lightningd: `psbt_compute_fee` assert overflow via crafted RBF prevtxs | High | **NOT FIXED** (assert intact in `.cold`; `handle_validate_rbf` still computes fee on peer-controlled PSBT) | Very high |
| 5 | channeld: `update_fee` → zero-output commitment → `assert(n>0)` | Medium | **NOT FIXED** (`full_channel.c`, `commit_tx.c`, `handle_peer_feechange` all unchanged; only indirect feerate-estimate ceiling) | Very high |
| 6 | dualopend: `tx_add_output` value > 21M → libwally assert | Medium | **NOT FIXED** (no bound before `psbt_append_output`; assert intact) | Very high |
| 7 | dualopend: `minimum_depth` bypass via reconnect | Medium | **NOT FIXED** (`channel->scid != NULL` still drives `channel_ready[LOCAL]`; `do_reconnect_dance` retransmits verbatim) | Very high |
| 8 | channeld: `update_view_from_inflights` wrong variable + cross-wired indices | Medium | **NOT FIXED** (instruction-level identical logic) | Very high |
| 9 | channeld: `start_batch` batch_size=0 heap OOB write | Low | **FIXED** (`batch_size < 2` rejected) | Very high |
| 10 | channeld: splice accepter never stores negotiated feerate | Low | **PARTIAL** (announce-time min/max validation added; feerate still not stored → min-fee check on the actual tx still vacuous) | High |
| 11 | onchaind: (a) THEIR_HTLC spend never resolves; (b) `handle_preimage` return-vs-continue | Low | **(a) NOT FIXED, (b) FIXED** | High |

**Score vs our source audit: 4 of 11 fully fixed, 1 partially, 6 not fixed.** The two loss-of-funds bugs (#1, #2) are fixed; all four crash/assert bugs we reported (#4, #5, #6, and partially #9's stall vector) survive except #9's OOB.

The release also contains fixes for bugs **not in our audit** (section 3) — including two we outright missed: an RPC-reachable `assert()` crash (`listpeerchannels` on a channel whose last funding feerate exceeds ~171.8M sat/kw) and an unbounded `open_channel2` inflight-spawn DoS limiter.

---

## 1. Method

1. **Triage:** all binaries are ELF, **not stripped, with full DWARF debug_info** — function names, source file:line attribution, and struct layouts are recoverable. This makes binary analysis highly feasible.
2. **Build-flag delta discovered:** unpatched = `gcc 15.2.0 -Og`, patched = `gcc 15.2.0 -O3` (both `-D_FORTIFY_SOURCE=3`, `-fstack-protector-strong`, same comp_dir `/home/clightning`). Consequence: function *sizes* are useless as a diff signal (-O3 inlines aggressively, splits `.cold` sections); all verdicts below are based on **(a) string/xref diffs, (b) DWARF `DW_AT_decl_line` shift maps per file (insertion-point fingerprints), (c) instruction-level comparison of the specific vulnerable code, (d) DWARF struct-member recovery**.
3. Tools: GNU binutils 2.47 (objdump/readelf/nm work for both x86-64 and aarch64 here), plus a venv with pyelftools + capstone (`analysis/kimi-k3/.venv`) for scripted DWARF analysis. All scratch data in `analysis/kimi-k3/tmp/`.
4. Version strings confirm: `v26.06.6` (unpatched) / `v26.06.7` (both patched dirs).

Note: the prompt's tarball→directory mapping appears swapped: `amd64-patched/` actually contains x86-64 binaries (per `file`), and `arm64-patched/` contains aarch64. I analyzed content, not tarball names.

---

## 2. Per-bug verification with binary evidence

### Bug 1 (Critical) — closingd mutual-close fee: **FIXED**

Three independent layers, all new in v26.06.7:

1. **closingd refuses to sign fees above our max.** DWARF shift map of `closingd.c`: +9 lines inserted inside `send_offer` (decl stays at 130 both builds; next function `tell_master_their_offer` 209→218). Patched `send_offer` (+0x55…): `closingd.c:155-156`:
   ```
   call amount_sat_greater        ; (fee_to_offer, max_fee)
   test %al,%al / jne →
   peer_failed_warn(pps, channel_id, "Fee %s became larger than our max fee %s", ...)   ; NEW string, .rodata 0x924a0, xref 0x7130
   ```
   `send_offer` is the single signing funnel for both the legacy loop and quickclose, so the escalation ("within 1 sat, agree") can no longer emit a signature on a >max fee. Second insertion of +2 lines in the `do_quickclose` region (pivot ≈ unpatched `:748-754`, the overlap clamp).
2. **lightningd enforces a max fee for the peer's signed close.** New function `calc_max_close_feerate()` (patched `closing_control.c:198`), and `closing_fee_is_acceptable` (patched `:217`) now computes `max_fee = amount_tx_fee(max_feerate, weight)` and returns false with the NEW log `"... That's above our max %s for weight %lu at feerate %u"` (patched `.rodata` 0x1fe268; xref 0xa687a, inside inlined `closing_msg`). This kills the `channel->last_tx` poisoning (the >max tx is never saved).
3. **New `close_tx_check()`** (patched `closing_control.c:276`, ~50 lines), called from `peer_received_closing_signature` (patched `:344-346`, `call close_tx_check` at 0xa64a6) before the pre-existing `check_tx_sig`. New strings: `"expected 1 input, got %zu"`, `"does not spend funding outpoint %s"`, `"output %zu has no script"`, `"output %zu goes to unknown script %s"`, and the reject path `"Bad closing_received_signature: %s"`. The close tx must have exactly 1 input spending the funding outpoint and only known-script outputs.
4. **hsmd signer backstop NOT added:** `libhsmd.c` is completely unchanged (zero function decl-line shifts), i.e. `handle_sign_mutual_close_tx` still signs blindly — acceptable now because closingd never asks for a >max signature.

### Bug 2 (High) — `check_tx_abort` wrong variable: **FIXED**

Unpatched (`-Og`, `channeld.c:1882-1895` at 0x4692+):
```
mov $0x0,%r13d                  ; inflight = NULL           (line 1882)
loop: mov (%rax),%r15           ; itr = inflights[i]        (1884)
      mov %r13,%rsi; call have_i_signed_inflight   (1887)  <-- passes the OUTER variable (NULL on first match)
      mov %r15,%r13             ; inflight = itr   (1895, after the check)
```
Patched (`check_tx_abort.part.0`): inlined `have_i_signed_inflight` operates on the **current loop entry** (`psbt_input_have_signature(itr->psbt, …)` on `%rbx`), and additionally tests `itr->i_sent_sigs` (byte at struct inflight +0xe0 — confirmed via DWARF; identical struct layout in both builds):
```
cmpb $0x0,0x38(%rsp) → jne error   ; have_i_signed_inflight(itr) result   (patched channeld.c:1941)
cmpb $0x0,0xe0(%rbx) → jne error   ; itr->i_sent_sigs                     (belt and suspenders)
error: peer_failed_err("tx_abort is not allowed after I have sent my signature. ...")
```
Decl-line map: +2 lines inside `check_tx_abort` (check_tx_abort p=1926, splice_abort +56→shift boundary). Same fix verified on arm64-patched (`psbt_input_have_signature` on the current inflight at `check_tx_abort.part.0+0x144`, `ldrb [x23,#224]` = `i_sent_sigs`, `peer_failed_err` with the same string).

### Bug 3 (High) — RBF-after-mine phantom funding: **NOT FIXED**

- `handle_commit_ready` RBF branch (patched `dual_open_control.c:3598`): `cmp $0xc,%eax; jne .cold` — i.e. the same `assert(channel->state == DUALOPEND_AWAITING_LOCKIN)` (12 = DUALOPEND_AWAITING_LOCKIN per `channel_state.h`), no `scid`-based refusal; then unconditional `wallet_update_channel`.
- `wallet_update_channel`: identical unconditional `channel->funding = *funding` clobber; line coverage 1:1 (shift +1), no guard added.
- `dualopend_depth_reached` wire format unchanged (u16 msgtype + u32 depth in both; no txid bound in).
- `peer_restart_dualopend`: still computes `channel->scid != NULL` (struct channel `scid` at +0x980 per DWARF; `cmpq $0x0,0x980(%rbp); setne`) and passes it as `channel_ready[LOCAL]`.
- dualopend `rbf_remote_start` (+7 lines) only gained a **feerate** range check (see §3.4), not a mined-candidate check.
- **Mitigating addition (not a fix):** NEW `channel_watch_inflight_outs()` (patched `peer_control.c:2623`) registers a `watch_txo(…, &inflight->funding->outpoint, funding_spent)` for every pending inflight, called from `handle_add_inflight` / `handle_update_inflight` / `opening_fundee_finished` / `opening_funder_finished` / `json_recoverchannel`. A pending funding candidate's outpoint being spent onchain now triggers the funding-spent pipeline — the node would at least *detect* the broadcast of a signed candidate it forgot. The protocol-level hole (locking in a candidate that never mined) remains.

### Bug 4 (High) — `psbt_compute_fee` overflow assert: **NOT FIXED**

- `bitcoin/psbt.c` has zero decl-line shifts in lightningd; the input-sum assert is still `__assert_fail` (patched psbt.c:1019, `psbt_compute_fee.cold` at 0x89f1a). `psbt_input_get_amount` still reads `prev_tx->outputs[idx].satoshi` raw (its own asserts/abort moved to `.cold` — same semantics).
- `handle_validate_rbf` (patched `dual_open_control.c:2307+`) still does `psbt_compute_fee(candidate_psbt)` on the peer-supplied PSBT: `ad968: mov 0x68(%rsp),%rdi; call psbt_compute_fee` (0x68(%rsp) = the fromwire'd candidate), before dualopend's own checked `check_balances` (ordering unchanged: `rbf_wrap_up` same size).
- Same on arm64-patched (`__assert_fail` ×2 in `psbt_compute_fee`).

### Bug 5 (Medium) — update_fee zero-output assert: **NOT FIXED**

- `channeld/full_channel.c`: **zero** decl-line shifts; `can_opener_afford_feerate`, `channel_update_feerate`, `approx_max_feerate` untouched. `channeld/commit_tx.c`: unchanged — `assert(n > 0)` at commit_tx.c:398 stands.
- `handle_peer_feechange` logic identical: parse → non-opener reject → `feerate_same_or_better(accepted_feerate_min/max)` → `channel_update_feerate` → `"update_fee %u unaffordable"`. The only diff is that the min/max field reads go through new helpers `accepted_feerate_min()`/`accepted_feerate_max()` (patched channeld.c:721/728), which return `[1, 1000000]` only when the new `peer->ignore_fee_limits` is set.
- *Indirect dampening only:* feerate estimates from bitcoind are now clamped at 1,000,000 sat/kw (§3.3), so `feerate_max()` is bounded by multiplier×1M instead of unbounded — still plenty to zero out a small lopsided channel. The zero-output band is not closed.

### Bug 6 (Medium) — `tx_add_output` > 21M: **NOT FIXED**

- Patched dualopend `run_tx_interactive` WIRE_TX_ADD_OUTPUT handler (patched `dualopend.c:1979-2037`): `amount_sat(value)` (2025) → `is_known_scripttype` (2031) → `psbt_append_output` (2036) — **no `max_supply` comparison** anywhere. The 21M-sat constant `0x775f05a074000` appears exactly 9× in both dualopend builds, all inside vendored libwally.
- `psbt_add_output`'s `assert(wally_err == WALLY_OK)` survives (in `.cold`). Remote dualopend crash primitive intact.

### Bug 7 (Medium) — minimum_depth bypass: **NOT FIXED**

- lightningd `peer_restart_dualopend`: `channel->scid != NULL` still passed as `channel_ready[LOCAL]` (see Bug 3 evidence). Function body effectively unchanged (the +5-line insertion before it is in `dualopen_errmsg`/dev-seed helpers).
- dualopend `do_reconnect_dance` (patched `dualopend.c:4169-4173`): `cmpb $0x0,0x410(%rbx); jne → status_debug("Retransmitting channel_ready for channel %s"); call send_channel_ready` — identical semantics (struct state `channel_ready` at +0x410 patched / +0x408 unpatched). No depth recheck anywhere (string sets for depth/minimum_depth identical).

### Bug 8 (Medium) — `update_view_from_inflights`: **NOT FIXED**

Instruction-level match of the whole function (patched channeld.c:3797-3818 vs unpatched 3723-3744): still reads `inflights[i]->amnt.satoshis` (+0x68 — the *total*, per DWARF identical struct inflight in both builds) for the LOCAL entries, still compares `[REMOTE][REMOTE]` (+0x3a0) but stores `[REMOTE][LOCAL]` (+0x398), still keeps last-negative instead of min for the cross-wired pair. Decl-shift map shows +8 lines inserted *before* it (inside `check_balances`), none inside the function itself.

### Bug 9 (Low) — start_batch batch_size=0: **FIXED**

Patched `handle_peer_start_batch` (channeld.c:2559-2560):
```
movzwl 0x68(%rsp),%eax     ; batch_size
cmp $0x1,%ax
jbe → peer_failed_warn(peer->pps, &peer->channel_id, "Don't send a start_batch with batch sizebelow 2")   ; NEW string .rodata 0xbea70
```
(the "sizebelow" typo — concatenated `"batch size" "below 2"` — is in the binary). The zero-length tal array OOB write is dead. Note: the secondary stall vector (unbounded synchronous reads of up to 65535 batched messages while a splice is inflight) does **not** appear to have a new timeout/cap.

### Bug 10 (Low) — splice accepter feerate: **PARTIAL**

- Patched `splice_accepter` (channeld.c:4360/4367): `if (funding_feerate_perkw < accepted_feerate_min(peer)) peer_failed_warn("Splice feerate_perkw %u is below our minimum %u")`; `if (> accepted_feerate_max) peer_failed_warn("... above our maximum %u")`. (Replaces the old lower-bound-only `"Splice feerate_perkw is too low"`.)
- Patched `handle_splice_init` (5109/5124): our own splice feerate is range-checked and capped at `proposed_feerate_max(peer)` = `peer->our_feerate_max` (new struct field, +0x4c): `"Feerate %u is too high. Higher than the most we'll pay ourselves %u"`.
- **But** the core defect persists: no store to `splicing->feerate_per_kw` (+0x50) anywhere in the accepter path (verified by register-tracking every `peer->splicing` load in the patched binary); `check_balances` still computes `min_*_fee = amount_tx_fee(splicing->feerate_per_kw /* =0 for accepter */, weight)` (patched channeld.c:3661/3663) → min-fee check on the actual transaction still vacuous. An initiator can still announce a sane feerate and build a near-zero-fee tx (pinning). The max direction tightened: `max_*_fee` now use `proposed_feerate_max` (our_feerate_max) instead of `feerate_max` (patched channeld.c:3673/3677).

### Bug 11 (Low) — onchaind: **(a) NOT FIXED, (b) FIXED**

- (a) `output_spent`'s THEIR_HTLC non-revoked branch is unchanged in structure (still just `onchain_annotate_txout(... TX_CHANNEL_HTLC_TIMEOUT|TX_THEIRS)`); `resolve_their_htlc` has exactly 2 call sites in both builds. A peer's winning HTLC-timeout spend still never resolves a live fulfill proposal → channel can hang in ONCHAIN.
- (b) `handle_preimage`: unpatched `status_broken("HTLC already resolved by %s…")` falls into the **function epilogue** (`return` — skips later duplicate-rhash HTLCs); patched (onchaind.c:1494→1497) jumps **backwards into the loop** (`continue`). Duplicate payment-hash HTLCs now all get their fulfill proposal.
- Also in onchaind.c: `is_mutual_close` grew +14 lines (the only net change; tightened mutual-close recognition — consistent with the closing-tx validation theme of the release; not one of our 11).

---

## 3. Fixes in v26.06.7 that are NOT in our audit list

These were found by diffing the binaries' DWARF/strings and cross-referencing the public unpatched source (all are real source-level changes, not optimizer artifacts):

1. **Per-peer inflight-open limit (DoS).** `handle_peer_spoke` (peer_control.c) gained ~44 lines: new helpers `num_inflight_opens()` and `channel_state_opening()`, rejecting `open_channel2` beyond a cap: `"Too many inflight channel opens (max %u)"` / `"Rejecting open_channel2 %s: too many inflight opens (%zu)"`. Unpatched spawns a dualopend + allocates a channel per `open_channel2` with no limit — a peer-triggerable memory/process-exhaustion DoS. **We missed this.**
2. **`next_feerate = last * 25 / 24; assert(next_feerate > last)` overflow crash — two sites.** New checked helper `next_funding_feerate()` (common/feerate.c, returns bool) replaces the asserting inline math in:
   - `json_openchannel_bump` (dual_open_control.c:2598) → now `command_fail("Can't calculate the next feerate: the last funding feerate recorded for this channel (%u) is out of range")` and a cap `our_feerate_max` (`"Feerate %u is above the most we'll pay (%u); the last attempt was at %u"`).
   - `json_add_channel` / **listpeerchannels** (peer_control.c:1070-1071) → now `"Funding feerate %u leaves no valid next feerate: omitting next_feerate"`.
   The listpeerchannels one is a **user/RPC-triggerable lightningd crash** whenever a channel's recorded last funding feerate exceeds ~171.8M sat/kw (reachable via a peer-proposed RBF feerate, which was unvalidated pre-patch — see #4). **We missed both sites** (our audit's RBF overflow finding was the *dualopend* `check_funding_feerate` path, whose message was merely reworded: `"Overflow calculating next feerate"` → `"Can't calculate next feerate. last %u"`).
3. **Feerate sanity ceiling at the estimate source.** bitcoind.c `estimatefees_callback`/`parse_feerate_ranges`: clamp at 1,000,000 sat/kw — `"Feerate floor (%u) is above sanity ceiling (%u): clamping!"` / `"Feerate for %u blocks (%u) is above sanity ceiling (%u): clamping!"`. Bounds `feerate_max()` downstream.
4. **dualopend accepter-side feerate validation** (our "hardening note", now fixed): new `accepted_feerate_min`/`accepted_feerate_max`/`feerate_in_range` (dualopend.c:434/441/455, floor 253 sat/kw, cap = `state->feerate_max` or 1M under ignore_fee_limits), enforced in `accepter_start` (+22 lines) and `rbf_remote_start` (+7 lines): `"%s %u below minimum %u"` / `"%s %u above maximum %u"` via `negotiation_failed`.
5. **`our_feerate_max` plumbing.** New `our_feerate_max()` in chaintopology.c (≈ `min(max_estimate × multiplier, 100 000)` sat/kw, default 100 000 when unknown); `channeld_feerates` wire message extended (7×u32 + bool — now also carries `our_feerate_max` and `ignore_fee_limits`); channeld `struct peer` gained `our_feerate_max` + `ignore_fee_limits`; used to cap splice fees and default open fees. (Verified by DWARF struct recovery and the fromwire/towire disassembly.)
6. **Reestablish `next_revocation_number` bound** (channeld `check_future_dataloss_fields`, patched channeld.c:5591-5592): `if ((next_revocation_number - 1) >> 48) peer_failed_err("Invalid next_revocation_number value")` — enforces the BOLT 48-bit commitment-number bound before calling into hsmd's shachain secret derivation. Peer-triggerable via a crafted `channel_reestablish`. **We audited this area as sound; we missed it.**
7. **STFU/quiescence anti-griefing** (channeld): new `stfu_did_timeout()` → `peer_failed_warn("STFU mode timed out.")` — a peer stalling the splice STFU dance no longer wedges the channel forever; `"Double STFU issue detected"` (peer_failed_warn); `"Cannot resume splice that we havent started"` guard in `splice_initiator`.
8. **Closing-tx / mutual-close recognition hardening:** lightningd `close_tx_check` (§2 Bug 1) plus onchaind `is_mutual_close` +14 lines.
9. **DNS/wireaddr validation:** `parse_wireaddr` (common/wireaddr.c) now actually calls `is_dnsaddr()` — which existed in the unpatched source but was *dead code* (never called outside tests; gc'd from the unpatched binary entirely) — plus a 255-byte hostname cap: `"dns: '%s' is not a hostname"` (connectd + gossipd), `"Connected out for %s error: hostname too long for socks5 request"` (connectd). Hardens gossip-learned/RPC addresses before DNS/SOCKS5 use. **Not in our audit** (outside the money paths we scoped).
10. **Onchain reorg/onchaind-replay robustness:** new `onchaind_restart`/`reorg_restart_onchaind` in onchain_control.c (+~86 lines at file tail), new `channel.onchaind_replay_height` field (DWARF-confirmed; struct channel grew 8 bytes before `our_funds`), new logs `"Chain reorganization: did not restart onchaind"` / `"Replay reached end of chain at block %u"`.
11. **DB shachain integrity bound:** `wallet_shachain_load` now `db_fatal("shachain_known pos %i out of range", pos)` for pos > 48 — bounds a loaded position before indexing `chain.known[]` (DB-corruption hardening, not P2P).
12. **Loss-visibility log:** `onchain_fulfilled_htlc` (peer_htlcs.c:1722 patched) now screams `"FUNDS LOSS of %s: peer took funds onchain with preimage, but we already failed the incoming HTLC"` instead of silently `continue`-ing when the incoming side was already failed. Detection, not prevention.
13. Minor: `json_parse_simple.c` +`bounded_datum_len`; `log.c` +`param_getloglevel`; hsmd.c `report_bad_req` refactor (no behavior change); wallet.c small (+5/+8/+10) edits; `migrations.c` one function +34 (schema migration, no new ALTER TABLE string — likely a data backfill).
14. **Wire format changes (compat-relevant):** `channeld_feerates` extended (see #5); dualopend/openingd wiregen line shifts (reinit messages carry the same fields; no new txid binding in `dualopend_depth_reached`).

Not observed in either build's C code: any change to `hsmd/libhsmd.c` (signer), `common/amount.c`, `onchaind` penalty machinery, `connectd`'s crypto paths, or `gossipd`'s signature checks (gossipd's only message-level addition is `"Unknown UTXO %s"` diagnostics in `gossmap_manage_channel_announcement`).

---

## 4. arm64-patched parity

- Same version string `v26.06.7`, same `gcc 15.2.0 -O3` flags (aarch64 variant), same fix strings in all daemons ("Fee %s became larger than our max fee %s", "batch sizebelow 2", "Splice feerate_perkw %u is above our maximum %u", "That's above our max…", "too many inflight opens", "is not shaped like a closing transaction" — wait, this one's actual form is "expected 1 input, got %zu" plus the funding-outpoint/script checks — all present).
- `check_tx_abort` fix verified instruction-level on aarch64 (current-inflight + `i_sent_sigs`).
- `psbt_compute_fee` asserts still present on aarch64 (Bug 4 unfixed there too).
- Verdicts in §2 apply identically to arm64.

---

## 5. CVE guesses

The binary alone cannot reveal CVE IDs; these are informed guesses based on what a CLN security point-release would assign. Committing to these guesses (not releasing) per the OTS plan:

**Almost certainly CVE'd (loss-of-funds, peer-exploitable, silently dangerous):**
1. **Bug 1** — unbounded mutual-close fee negotiation → up to 100 % funder-balance burn. *(Guess: the headline CVE of this release.)*
2. **Bug 2** — `tx_abort`-after-`tx_signatures` splice deletion → peer holds a fully-signed tx spending the live funding output. 

**Possibly CVE'd (remote/DoS crash fixes present in the binary):**
3. **Bug 9** — `start_batch` batch_size<2 heap OOB write (peer-triggerable memory corruption primitive).
4. The **reestablish `next_revocation_number` bound** (§3.6) — peer-triggerable hsmd/channeld misuse crash.
5. The **RBF/`listpeerchannels` `next_feerate` overflow assert** (§3.2) — lightningd crash.
6. The **inflight-open limit** (§3.1) — unauthenticated-ish peer DoS.

**Probably not CVE'd (hardening):** feerate ceilings/`our_feerate_max` plumbing, dualopend/splice feerate validations, STFU timeout, `close_tx_check`/`is_mutual_close` shape checks (these two are arguably part of the Bug-1 CVE fix), wireaddr DNS validation, onchaind replay, wallet shachain bound, FUNDS LOSS log.

**Guess at count:** 2 CVEs minimum (Bugs 1+2), plausibly 3-5 if the maintainers also assigned IDs to the crash fixes (#9, §3.2, §3.6) and/or the open-DoS (§3.1). If the release notes bundle under one "security" umbrella: 1-2. Plausible ID shape: CVE-2026-2xxxx … CVE-2026-4xxxx (assigned mid-2026). **Notably: Bugs 3-8 (incl. the lightningd remote crash #4 and the dualopend crash #6) are NOT fixed in v26.06.7** — if they ever get fixed/assigned, it will be a later release; we hold OTS-committed prior knowledge of them.

---

## 6. Feasibility verdict (for the benchmark)

Binary analysis of CLN release binaries by an AI model is **very feasible when the binaries ship with symbols + DWARF** (these do): every one of the 11 known bugs could be definitively verified fixed/not-fixed, and 10+ additional real source changes were recovered without any source for the patched tree. The -Og→-O3 flag change between builds defeated naive size/hash diffing but not string-xref + decl-line-shift + struct-layout analysis. Cost drivers: -O3 inlining scatters functions (everything into `peer_in`/`main`/`closing_msg`), so per-function evidence requires chasing inline instances via line tables.

**Artifacts:** scratch/dumps/scripts in `analysis/kimi-k3/tmp/`; Python venv in `analysis/kimi-k3/.venv`.
