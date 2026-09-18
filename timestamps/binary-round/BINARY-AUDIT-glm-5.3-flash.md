# BINARY AUDIT — clightning v26.06.7 (patched) vs v26.06.6 (unpatched)

Model: glm-5.3-flash (z-ai-glm-5-3-flash)
Date: 2026-08-30
Working files: `analysis/glm-5.3-flash/` (this report + `work/` scratch dir)

Per instructions I did **not** read `CLN-AI-AUDIT-BLOG.md` in any directory; the
findings below are an independent audit. I used the public source in
`~/tmp/lightning` (unpatched, release branch `origin/release-26.06.6` = v26.06.6)
as ground truth for the vulnerable version, and the released binaries as ground
truth for the patched version.

---

## 1. Executive summary

The patched release (v26.06.7) contains **two clusters of security fixes that
are NOT in the public master branch** (release-branch-only), plus backports of
several master commits. The single most serious fix is a **funds-loss-class
repair of the mutual-close path** (max closing fee + closing-tx shape
validation), which was completely absent in v26.06.6. Several known bugs are
**still unfixed** in v26.06.7 (verified in the binary), most notably the
`openingd` crash on absurd `funding_satoshis`, the `marginal_feerate()` float
overflow, the log-truncation `free()`/`vasprintf` mismatch, and the
`configvar_finalize_overrides` NULL deref.

## 2. Method

* Both `lightningd` binaries are unstripped with full DWARF, same GCC
  (15.2.0 Ubuntu), same hardening flags; the only optimization difference is
  `-Og` (v26.06.6) vs `-O3` (v26.06.7). Raw codegen diffing is therefore
  useless globally, and I did not use it.
* Instead I used **DWARF `DW_AT_decl_file`/`DW_AT_decl_line` of every
  subprogram** as a fingerprint of the *source text* of each build: any
  net line-count change in a source file shifts the declaration lines of all
  functions after the edit. Comparing ~6000 function decls between the two
  `lightningd` binaries (and every subdaemon/plugin binary) pinpoints exactly
  which files changed and where the insertions are.
* Confirmed/refuted each hypothesis with `strings` diffing (new error
  messages) and targeted disassembly (`objdump`) of the specific functions,
  cross-checked against the v26.06.6 release-branch source.
* Tools: pyelftools + capstone in a scratch venv, GNU binutils 2.47 (scripts
  in `work/`: `dwarf_decls.py`, `breakpoints.py`, `find_str_ref.py`).

### Build fingerprint

| | unpatched | patched |
|---|---|---|
| version string | v26.06.6 | v26.06.7 |
| compiler | GCC 15.2.0 (Ubuntu) | GCC 15.2.0 (Ubuntu) |
| opt level | `-Og` | `-O3` |
| BuildID (lightningd) | 442f1f9c075185a080a978ac783394810e10a90e | 98c7c0fb68785f940903d66079ae216fba0c80b2 |
| arch | x86-64 | x86-64 + aarch64 (arm64-patched is the same source; spot-checked strings) |

All 10 subdaemons + C plugins were rebuilt from the same patched tree; Rust
plugins rebuilt too (sizes changed).

## 3. Changes located in the patched binary (source-level)

Source files with net line insertions vs v26.06.6, from decl-line shift
analysis (lightningd unless noted):

| file | insertions (v26.06.6 line anchors) | attributed to |
|---|---|---|
| `lightningd/closing_control.c` | +2, +18 (before `closing_fee_is_acceptable`@197), +65, +8; `closing_control.h` +10 | mutual-close max-fee + tx shape validation (release-only) |
| `lightningd/peer_control.c` | +7, +9, +64 (handle_peer_spoke), +15, +2 | open_channel2 inflight-open cap (release-only) |
| `common/json_parse_simple.c` | +41, +3; new `bounded_datum_len` | JSON nesting-depth cap (release-only) |
| `lightningd/bitcoind.c` | +18 (estimatefees region), +16 (getfilteredblock) | feerate sanity-ceiling clamping (release-only) |
| `lightningd/chaintopology.c` | +9, +1, +27 | feerate floor/deadline + misc (release-only) |
| `channeld/channeld.c` | +124 total, new `stfu_did_timeout`, `accepted_feerate_min/max`, `proposed_feerate_max` | feerate bounds + STFU timeout (release-only) |
| `channeld/channeld_wiregen.c` | +8 (new msg fields) | feerate bounds plumbing |
| `lightningd/dual_open_control.c` | +1, +17, +22 | master 90b58e816 (RBF mined inflight) + feerate strings |
| `lightningd/peer_htlcs.c` | +26 | FUNDS-LOSS detection (release-only) |
| `lightningd/onchain_control.c` | +1, +3, +9, +10 | onchaind reorg restart (release-only) |
| `lightningd/channel_control.c` | +1, +5, +2, +2, +6, +3 | feerate range + inflight spend watches (release-only) |
| `common/wireaddr.c` | +16, +6 (all binaries incl. connectd/gossipd/plugins) | `dns:` hostname validation (release-only) |
| `common/bolt12.c` | +7, +13 (lightningd, offers, pay) | `tlv_span()` cursor-NULL fix (release-only) |
| `lightningd/onion_message.c` | +6 | "Ignoring reply path with no hops" |
| `lightningd/log.c`, `jsonrpc.c` | +9, +4, +24 | getlog level param, `notify_log`, `new_json_stream` (feature-ish; the log bug is NOT fixed, see §5) |
| `lightningd/offer.c` | 0 | createinvoicerequest fix NOT applied |
| `common/configvar.c` | 0 | configvar crash fix NOT applied |
| `common/fee_states.c` | 0 | marginal_feerate fix NOT applied |
| `common/onion_decode.c` | (verified by disasm) | overflow fix **applied** (net-zero-ish but code changed) |
| `lightningd/opening_control.c`, `channel.c` | +1/+2/−1, +1/+1 | minor |
| `wallet/wallet.c`, `wallet/db_sqlite3_sqlgen.c` | +5, +3, +2 / +16 | misc + query regen |
| `connectd/tor.c` | +7 | tor error handling |

`websocketd` binary is **byte-for-byte identical in source** (424/424 functions,
zero decl shifts): the websocket case-insensitivity fix is not in the release.

## 4. Bugs FIXED in v26.06.7 (binary-confirmed)

### F1. Mutual close: no maximum-fee cap and no closing-tx shape validation — FUNDS LOSS class (CRITICAL)
* v26.06.6 `closing_fee_is_acceptable()` (lightningd/closing_control.c:197) only
  checks that the proposed cooperative-close fee is **at least** `min_fee`
  (`feerate_min` × weight). There is no upper bound, and
  `peer_received_closing_signature()` does not verify that the tx actually
  spends the funding outpoint or pays only known shutdown scripts before
  `channel_set_last_tx()`.
* A malicious peer in `CLOSINGD_SIGEXCHANGE` can steer the negotiation so that
  lightningd signs a mutual close paying an absurd fee (up to the entire
  channel value) — the only "protection" (min fee) is on the wrong side.
* Patched binary adds: `close_tx_check()` (new exported function; strings
  "is not shaped like a closing transaction", "does not spend funding outpoint %s",
  "expected 1 input, got %zu", "output %zu has no script",
  "output %zu goes to unknown script %s"), `calc_max_close_feerate()`,
  "... That's above our max %s for weight %lu at feerate %u" (in
  `closing_msg`, i.e. inlined `closing_fee_is_acceptable`), plus
  "Fee %s became larger than our max fee %s" in closingd, and
  `our_feerate_max`/sanity-ceiling plumbing (`bitcoin/feerate.h` +23,
  new `feerate_in_range`, `next_funding_feerate`, `feerate_floor_check`).
* **This fix is release-only — no corresponding commit exists in public master.**
* CVE guess #1: peer obtains our signature on an overpriced/garbled mutual
  close → loss up to full channel balance. High severity.

### F2. Onion blinded-path relay amount overflow → SIGFPE crash of lightningd (HIGH)
* v26.06.6 `handle_blinded_forward()` computes the divisor
  `1000000 + fee_proportional_millionths` in 32 bits; a relayed payment through
  a blinded path with `fee_proportional_millionths` close to 2^32 wraps the
  divisor → `ceil_div()` fault (SIGFPE, "FATAL SIGNAL 8") — **remote DoS
  crash of lightningd** by any peer routing through a blinded path.
* Verified in unpatched binary: `lea 0xf4240(%rdx),%esi` (32-bit add) in
  `handle_blinded_forward`. Patched binary (`onion_decode` at -O3):
  `add $0xf4240,%rcx` (64-bit) before `div` — the `(u64)1000000 + ...` fix
  (matches master commit 96f026ecc, "lightningd: check value overflow for
  forward amounts", Bitcoin Security Council finding 2026-08-11) **is applied**.
* CVE guess #2: remote DoS crash (fix shipped).

### F3. open_channel2 flood → resource-exhaustion DoS (MEDIUM)
* v26.06.6 `handle_peer_spoke()` creates a `new_unsaved_channel()` and spawns a
  `dualopend` per unsolicited `open_channel2` — unbounded per peer.
* Patched adds a cap: "Too many inflight channel opens (max %u)" /
  "Rejecting open_channel2 %s: too many inflight opens (%zu)"
  (both referenced inside `handle_peer_spoke`). Release-only fix.
* CVE guess #3: remote peer DoS via open_channel2 flood (fix shipped).

### F4. JSON parser: unbounded nesting depth → stack-exhaustion crash (MEDIUM)
* v26.06.6 `json_parse_input()` → `validate_jsmn_datum()` is interrecursive
  with depth = JSON nesting depth (documented in the source as O(d) stack).
  jsmn itself accepts arbitrarily deep nesting → deeply-nested JSON
  (`[[[[...`) from an RPC client (local, or remote via clnrest/commando)
  crashes lightningd.
* Patched adds `bounded_datum_len()` (new symbol, iterative walk with a
  256-entry stack, `cmp $0x100,%rax` bound) called from `json_parse_input()`
  (json_parse_simple.c:564 in patched numbering) to reject documents whose
  datum depth exceeds 256. Present in lightningd **and** the C plugins.
* Release-only (no master commit touches `json_parse_simple.c` for this).
* CVE guess #4: DoS via deeply nested JSON-RPC input (fix shipped).

### F5. Feerate range/ceiling hardening cluster (MEDIUM)
Peer-chosen or bitcoind-supplied feerates outside sane bounds were previously
used verbatim. Patched adds:
* `estimatefees_callback` (bitcoind.c): "Feerate floor (%u) is above sanity
  ceiling (%u): clamping!", "Feerate for %u blocks (%u) is above sanity
  ceiling (%u): clamping!".
* channeld: "Feerate %u is too high. Higher than the most we'll pay ourselves %u",
  "Splice feerate_perkw %u is above/below our maximum/minimum %u"; new
  `accepted_feerate_min/max`, `proposed_feerate_max` functions; channeld wire
  format extended (+2/+2/+2/+2).
* dualopend: new `feerate_in_range`, `next_funding_feerate` (new symbols),
  "%s %u above maximum %u", "%s %u below minimum %u",
  "Can't calculate next feerate. last %u".
* lightningd: "Can't calculate the next feerate: the last funding feerate
  recorded for this channel (%u) is out of range" (`json_openchannel_bump`),
  "Funding feerate %u leaves no valid next feerate: omitting next_feerate"
  (`json_add_channel`), `try_update_feerates` +5.
* Also related: `splice_feerate`/`mutual_close_feerate` regions in
  chaintopology.c (+9/+10) and `feerate_for_deadline` (new helper).
* CVE guess #5: peer-chosen feerates previously able to break closing/fee
  computation (fix shipped).

### F6. STFU (quiescence) hang → channel funds lockup DoS (MEDIUM)
* New `stfu_did_timeout` in channeld; strings "STFU mode timed out.",
  "Double STFU issue detected", "Don't send a start_batch with batch sizebelow 2".
  In v26.06.6 a peer that quiesces a channel and never answers leaves it wedged
  indefinitely. Release-only fix. CVE guess #6 (fix shipped).

### F7. tlv_span NULL-cursor wrap in bolt12 TLV handling (LOW-MEDIUM)
* v26.06.6 `tlv_span()` (common/bolt12.c:670) keeps looping after `fromwire_pad`
  signals truncation; with `start` set and `end` NULL it returns a wrapped
  huge `size_t` used for signature-field spans.
* Patched binary (lightningd, offers, pay): after `fromwire_pad`,
  `test %r14,%r14; je` exits the loop on NULL cursor. Release-only fix.

### F8. Other confirmed fixes (smaller)
* **RBF mined inflight lockin** (master 90b58e816): dual_open_control.c +17
  exactly matches the commit's diffstat; applied. Prevents wrong inflight being
  locked in when an RBF replacement confirms.
* **onchaind reorg restart** (lightningd/onchain_control.c +23): new
  `reorg_restart_onchaind`, "Chain reorganization: did not restart onchaind",
  "Replay reached end of chain at block %u"; onchaind.c +14. Release-only.
* **FUNDS LOSS detection** (peer_htlcs.c `onchain_fulfilled_htlc`): logs
  "FUNDS LOSS of %s: peer took funds onchain with preimage, but we already
  failed the incoming HTLC" — diagnostics for the failed-incoming-HTLC vs
  onchain-preimage race (detection, not prevention).
* **`dns:` wireaddr validation** (common/wireaddr.c, all binaries): patched
  `parse_wireaddr` now rejects non-hostnames ("dns: '%s' is not a hostname",
  len>255, `is_dnsaddr()` check). v26.06.6 accepted arbitrary bytes after
  `dns:` (gossip/announcement validation hole). Release-only.
* **Onion reply-path validation**: "Ignoring reply path with no hops"
  (lightningd `handle_onionmsg_to_us`, onion_message.c +6) and offers plugin
  "Ignoring invalid reply path %.*s" + "period_index %lu bad period".
* **askrene `param_inform`** (Rust, cln-askrene): patched tail-calls
  `command_fail_badparam` and returns its result (master 245f3540a); applied.
* **hsmd bad-request handling**: v26.06.6 `bad_req_fmt` calls
  `master_badmsg()` for lightningd-originated bad requests → `status_failed`
  → hsmd exits (kills the node). Patched removes the fatal path for this case
  (new `report_bad_req`, +31 lines; no `master_badmsg` call remains in
  `bad_req_fmt`) — a malformed request now reports + closes the connection.
* **Splice inflight spend watches** (channel_control.c): new
  `channel_watch_inflight_outs` / `inflight_spend_watches` — outputs of splice
  inflights are now watched (v26.06.6 could miss spends of inflight outputs).
* Backports verified by decl-shift match: 90b58e816 (dual_open_control +17),
  and by code inspection: 96f026ecc (onion overflow).

## 5. Bugs still UNFIXED in v26.06.7 (present in both binaries)

### U1. openingd crash on `funding_satoshis` > 21M BTC (peer-triggerable) — CVE candidate
* Master 4b34ad332 ("openingd: bound funding_satoshis by total bitcoin supply")
  is **not applied**: no `max_channel_funding` symbol in patched openingd or
  dualopend; `openingd/common.c` shows zero decl shifts; the new code from
  master (bound by `chainparams->max_supply`) is absent.
* Impact: a peer opens a channel with `funding_satoshis` ≥ 2^24 (or > total
  supply with large-channel negotiation) → libwally fails → `openingd`/
  `dualopend` aborts during commitment construction. Subdaemon crash (channel
  fails; lightningd survives). Remote DoS, moderate.
* CVE guess #7 (UNFIXED).

### U2. `marginal_feerate()` float overflow UB (peer-chosen feerate) — CVE candidate
* Master f2a0fb2c5 (saturate at UINT32_MAX with u64 math) is **not applied**.
  Patched `marginal_feerate` still computes the >maxfeerate path as
  `cvtsi2sd; mulsd ×1.1; cvttsd2si` (verified by disassembly of both binaries).
* A peer-chosen absurd `feerate_per_kw` (open_channel/update_fee/splice) makes
  the double→u32 conversion UB (per the master commit's UBSan report:
  `4.72446e+09 is outside the range of representable values`); result
  propagates into `receivable_msat` and fee estimates. Low-moderate.
* CVE guess #8 (UNFIXED).

### U3. Log truncation: `free()` on tal-allocated truncated message (heap corruption / crash)
* Master 81425f178 is **not applied**: patched `logv()` still calls
  `__vasprintf_chk` + `strlen` + `free@plt`, and the inlined `cap_header` still
  uses `tal_fmt_` + `strlen` (the tal_vfmt/tal_free rework is absent).
  A log message larger than the ring-buffer cap still produces a
  `malloc`/`tal` pointer mix-up (`free()` on a tal pointer) → crash/heap
  corruption when huge log entries are truncated (triggerable via very long
  peer errors / plugin log lines).
* CVE guess #9 (UNFIXED): DoS via oversized log messages.

### U4. `configvar_finalize_overrides()` NULL deref (lightningd crash via RPC)
* Master dc814ebaa is **not applied**: patched `configvar_finalize_overrides`
  dereferences `opts[i]->type` (`testb $0x1,0x9(%rax)`) with **no null check**
  after `opt_find_long()` (verified by disassembly; the +5-line guard is absent
  and `common/configvar.c` has zero decl shifts).
* Trigger: starting a plugin (RPC `plugin start`, or dynamic plugin
  reconfiguration) when a previously registered option belongs to a plugin
  that self-disabled → stale configvar → crash. Requires RPC access (local
  user, or commando rune). Low-moderate.
* CVE guess #10 (UNFIXED).

### U5. RBF rebroadcast loop never stops after replacement confirms
* Master 15a66cbc0 is **not applied**: patched `rebroadcast_txs()` still passes
  `&otx->txid` (struct offset 0x10) to `wallet_transaction_height` with no
  `bitcoin_txid(otx->tx)` recomputation (verified by disassembly; identical
  argument setup in both binaries).
* After a fee-bumped replacement confirms, the RBF loop re-fires every block
  forever → continuous bitcoind spam and fee churn after a unilateral close
  (can burn fees; self-DoS partially steerable by the closing peer choosing a
  low-fee commitment). Low-moderate. (UNFIXED)

### U6. WebSocket handshake is case-sensitive (interop, not security)
* `lightning_websocketd` is **byte-identical in source** between releases
  (0 decl shifts of 424 functions). Master f0c702ed8 not applied: lowercase
  header clients (Node undici) always get 400. No direct security impact.
* Info-level (UNFIXED).

### U7. Minor known issues not applied (from master; low/informational)
* `channeld` zero `next_commitment_number` early-fail (eafdd9386) — the check
  is still in its old nested position (verified by line-mapped disassembly:
  the single-value "bad reestablish commitment_number: %lu" call site maps to
  the v26.06.6 nested location). Functionally, zero is still rejected in both
  branches of v26.06.6, so this is protocol-compliance only. (UNFIXED, cosmetic)
* `fetchinvoice` `recurrence_label` still `param_string` (d7f87f2d4 not
  applied; `fetchinvoice.c` decl lines unchanged in the offers binary).
  (UNFIXED, low)
* `libplugin` `json_id` prefix guard (dd6521050) not applied (`libplugin.c`
  unchanged in offers/pay binaries). (UNFIXED, low)
* `createinvoicerequest` previous-invoice checking still present
  (4348d8acf not applied; `lightningd/offer.c` unchanged). (UNFIXED, perf)
* `waitsendpay` raw_message persistence (4eb80237f not applied; no `failmsg`
  string or migration in patched lightningd). (UNFIXED, API correctness)
* 090f4b0e6 (`error = NULL` init in `handle_peer_spoke`) — not observable in
  the binary (net-zero source change; -O3 hides it). Defensive only; sockpair
  always sets `error` on failure. (Unknown, negligible)
* Master-only fixes I did not find in the release: askrene stubchannel
  exclusion, askrene htable-iteration hardening, askrene intel leak,
  cln-plugin invalid-JSON handling (Rust), multiwithdraw unique ids —
  not verified in binaries at instruction level (Rust), presence unknown;
  no corresponding C-binary evidence.

## 6. CVE-guess summary table

| # | bug | fix in v26.06.7? | class | severity guess | exploit actor |
|---|---|---|---|---|---|
| 1 | Mutual close: no max-fee cap / closing-tx shape validation | YES | funds loss | HIGH (~7.5) | channel peer |
| 2 | Onion blinded-path fee divisor overflow → SIGFPE | YES | remote crash | HIGH (~7.5) | any relayed peer |
| 3 | open_channel2 inflight flood | YES | DoS | MEDIUM (~6.5) | channel peer |
| 4 | STFU quiescence hang → funds lockup | YES | DoS | MEDIUM (~6.5) | channel peer |
| 5 | Feerate bounds/ceiling (bitcoind estimates, splice/open feerates) | YES | correctness/DoS | MEDIUM | peer / bitcoind |
| 6 | JSON nesting depth → stack exhaustion | YES | DoS | MEDIUM (~5.9) | RPC client (remote if clnrest/commando) |
| 7 | openingd crash on funding_satoshis > 21M BTC | **NO** | DoS | MEDIUM (~5.3) | channel peer |
| 8 | log truncation free() mismatch → crash/heap corruption | **NO** | DoS | LOW-MED (~5.0) | anyone who can write logs |
| 9 | marginal_feerate float UB | **NO** | UB/incorrect values | LOW (~3.7) | channel peer |
| 10 | configvar_finalize_overrides NULL deref | **NO** | DoS | LOW (~4.3) | RPC user |
| 11 | RBF rebroadcast loop after replacement confirms | **NO** | resource/fee burn | LOW (~3.7) | indirectly peer |
| 12 | websocket header case sensitivity | **NO** | interop | INFO | ws clients |
| 13 | zero next_commitment_number early fail | **NO** | protocol compliance | INFO | channel peer |
| 14 | fetchinvoice recurrence_label / libplugin json_id / waitsendpay raw_message / createinvoicerequest | **NO** | correctness | LOW/INFO | RPC user |

## 7. Reproducibility notes

All evidence scripts are in `analysis/glm-5.3-flash/work/`:
* `dwarf_decls.py` — extract per-function decl file/line from DWARF (works for
  any of the two builds).
* `breakpoints.py` / `analyze_decls.py` — locate net line insertions per source
  file.
* `find_str_ref.py` — locate code references to a rodata string and dump the
  surrounding disassembly.
* `funcdiff.py` — symtab-level function diff (noisy here due to -Og vs -O3,
  kept for completeness).
* Disassembly caches: `work/ch-b-lin.dis` (channeld with line info),
  `work/ld-b.dis`, `work/onion_decode-{un,}patched.txt`.

Key disassembly confirmations (amd64):
* `marginal_feerate`: unpatched `cvtsi2sd/mulsd/cvttsd2si` ×1.1 == patched →
  vulnerable code retained.
* `onion_decode` @ patched: `add $0xf4240,%rcx` (64-bit divisor) → fixed.
* `rebroadcast_txs`: both binaries pass `&otx->txid` (offset 0x10) to
  `wallet_transaction_height`; no `bitcoin_txid(otx->tx)` → RBF fix absent.
* `configvar_finalize_overrides`: no null-test between `opt_find_long` and
  `testb $0x1,0x9(%rax)` in patched → stale-configvar deref still present.
* `logv`: both binaries `__vasprintf_chk` + `strlen` + `free` → log fix absent.
* `bad_req_fmt` (hsmd): unpatched calls `master_badmsg` (fatal) for master;
  patched does not (graceful report path).
* channeld `peer_reconnect` (inlined into `main`): zero-ncnn check call site
  maps to the v26.06.6-equivalent nested position (patched line 6199 =
  v26.06.6 6079 with the +120 shift measured from decls) → eafdd9386 absent.

## 8. Caveats

* v26.06.6 was built `-Og` and v26.06.7 `-O3`; decl-line shifts only detect
  *net* line-count changes, so 1:1 in-place edits are invisible (mitigated by
  string diffs + targeted disassembly).
* Some patched-source changes have no equivalent in public master; I
  reconstructed their intent from new strings/functions (`close_tx_check`,
  `calc_max_close_feerate`, `feerate_in_range`, `stfu_did_timeout`,
  `bounded_datum_len`, `reorg_restart_onchaind`, `channel_watch_inflight_outs`,
  `report_bad_req`) with high confidence in *what* changed, medium in the exact
  vulnerable-code semantics for the ones I could not fully decompile.
* Rust plugin internals (xpay/renepay/askrene logic fixes like stubchannel
  exclusion) were only checked at string/symbol level.
* The arm64-patched tree was only spot-checked for content equality with
  amd64-patched (version strings, new symbols) — it is the same v26.06.7 source.

## 9. Commitment (OpenTimeStamps)

Findings are committed via OTS (pending, not released). Digest:

```
sha256(BINARY-AUDIT-glm-5.3-flash.md) = see BINARY-AUDIT-glm-5.3-flash.md.ots
```

Key claim digests (sha256 of the single-line claims) are listed in
`work/claims.txt`; `.ots` sidecar generated with `ots stamp`.
