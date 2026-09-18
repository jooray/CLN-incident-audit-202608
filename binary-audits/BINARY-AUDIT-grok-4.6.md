# Binary audit: Core Lightning v26.06.7 vs AUDIT.md

**Model:** grok-4.6
**Date:** 2026-09-01
**Public tree used as a map:** `c1551c557` (`v26.06-273-gc1551c557`), the tree named in `AUDIT.md`
**Binaries (read-only):**
- Unpatched: `~/Downloads/amd64-unpatched` from `clightning-v26.06.6-Ubuntu-26.04-amd64.tar.xz` (mtime 2026-07-20). Version string `v26.06.6`.
- Patched: `~/Downloads/amd64-patched` from `clightning-v26.06.7-Ubuntu-26.04-amd64.tar.xz` (mtime 2026-08-26). Version string `v26.06.7`.
**Primary objects:** `usr/bin/lightningd` and `usr/libexec/c-lightning/lightning_{channeld,hsmd,openingd,dualopend,closingd,onchaind,connectd}`

This is a verification of `AUDIT.md` findings 1–10 against the embargoed v26.06.7 binary. It is not a live exploit run. Binaries, public source, and `AUDIT.md` were not modified. Scratch files live under `analysis/grok-4.6/`.

Public git tags `v26.06.6^{commit}` and `v26.06.7^{commit}` both resolve to `9f7baf66e1e6b421c0c81a3c3f7c307f8e78a911`. The patched source is absent from this history. DWARF in the patched binaries still names `/home/clightning/...` and line numbers, so the embargo hid the tarball, not the debug info.

---

## Scorecard

| ID | AUDIT finding | v26.06.7 binary | Confidence |
|---|---|---|---|
| 1 | `tx_abort` after we signed a splice drops tracking | **FIXED in `channeld`**. lightningd still deletes an inflight on abort with no `i_sent_sigs` guard (**PARTIAL** defense in depth). | high |
| 2 | `s64` balance wrap on peer `update_add_htlc` | **NOT FIXED** | high |
| 3 | HSM / `channeld` signs splices blindly | **NOT FIXED** | high |
| 4 | `lowest_splice_amnt` uses `amnt`, writes wrong slots | **NOT FIXED** | high |
| 5 | splice `tx_signatures` overwrites inflight txid | **FIXED** (parse destination is a stack local). No `bitcoin_txid_eq` of that field against the inflight. | high |
| 6 | blinded-path fee numerator wrap | **NOT FIXED** | high |
| 7 | watchtower splice / HTLC gap | **NOT FIXED** | high |
| 8 | `amount_msat_add_sat_s64` `INT64_MIN`; splice_locked raw `+=` | Helper source still identical (**NOT FIXED**). `-O3` overflow checks may reject `INT64_MIN` by accident. lightningd raw `+=` still present. | high on source identity; medium on accidental `INT64_MIN` reject |
| 9 | simple-close `close_tx_check` skips our output amount | `simple_close_control.c` is **absent** from both binaries. Patched lightningd adds `close_tx_check` in `closing_control.c` for classic mutual close: 1 input, spends funding, known scripts. **No `our_msat` compare.** | high |
| 10 | interactive-tx ignores `channel_id` | **NOT FIXED** | high |

The v26.06.7 point release addresses the critical splice-abort hole in `channeld` and the splice `tx_signatures` txid clobber. It does not close the high-severity HTLC wrap, the blind splice signature, or most of the medium/low items. `--offline` remains the operational mitigation for findings 2–4, 6, and 8 until those land.

---

## Method

Both builds ship unstripped ELF64 with DWARF (`-g`). Compiler is `GCC (Ubuntu 15.2.0-16ubuntu1) 15.2.0` in both. The unpatched producer string is `-Og`. The patched producer string is `-O3`. That single flag change inlines helpers, splits `.cold` / `.constprop` / `.isra` clones, and inflates `.text` even where source is unchanged. Size alone is not a patch.

Tools: `pyelftools` (SYMTAB, DWARF line programs, struct layouts), `/usr/bin/objdump -d -l` on symbol ranges, `strings` diffs, public HEAD as a line-number map. Full-CU DWARF walks are slow; targeted dumps by symbol address were used instead. Capstone listings of the same ranges sit in `analysis/grok-4.6/`.

Patched DWARF for `struct inflight` (channeld): `outpoint` +0, `remote_funding` +36, `amnt` +104 (`0x68`), `psbt` +120 (`0x78`), `splice_amnt` +128 (`0x80`), `i_sent_sigs` +224 (`0xe0`). That layout is the ruler for findings 1, 4, and 5.

`.text` growth (bytes):

| binary | v26.06.6 | v26.06.7 | delta |
|---|---|---|---|
| lightningd | 1,394,564 | 1,531,844 | +137,280 |
| lightning_channeld | 703,172 | 739,844 | +36,672 |
| lightning_hsmd | 601,028 | 624,772 | +23,744 |
| lightning_openingd | 585,220 | 606,084 | +20,864 |
| lightning_dualopend | 635,972 | 658,820 | +22,848 |
| lightning_closingd | 555,460 | 574,532 | +19,072 |
| lightning_onchaind | 576,836 | 607,044 | +30,208 |
| lightning_connectd | 459,396 | 502,148 | +42,752 |

DWARF max line vs public HEAD (selected CUs in the patched binaries):

| file | HEAD `wc -l` | patched DWARF max | note |
|---|---|---|---|
| `channeld.c` | 7126 | 7226 | ~100 lines of embargoed splice/STFU code |
| `channel_control.c` | 2858 | 2858 | same length as HEAD; abort still deletes |
| `peer_control.c` | 4142 | 4234 | +92; includes `channel_watch_inflight_outs` |
| `peer_htlcs.c` | 3303 | 3320 | +17; not an amount-gate rewrite |
| `dualopend.c` | 4535 | 4640 | +105; inflight-open / feerate strings |
| `libhsmd.c` | 2595 | 2595 | unchanged |
| `onion_decode.c` | 463 | 464 | wrap still compiled |
| `interactivetx.c` | 859 | 859 | unchanged |
| `amount.c` | 787 | 785 | helper still at 403–408 |
| `opening_common.c` | 171 | 171 | `max_htlc_value_in_flight = UINT64_MAX` still expected |
| `simple_close_control.c` | 356 | 0 | file not in these binaries |
| `closing_control.c` | 888 | 977 | patched `close_tx_check` lives here |

New patched-only `channeld` strings (absent from public source): `Cannot resume splice that we havent started`, `Double STFU issue detected`, `STFU mode timed out.`, `Invalid next_revocation_number value`, `Don't send a start_batch with batch sizebelow 2`, `Splice feerate_perkw %u is above our maximum %u`, `Splice feerate_perkw %u is below our minimum %u`.

Do not treat `Signed PSBT txid %s does not match current_psbt_txid %s` as the Finding 5 patch. That string is in both binaries and in HEAD `channeld.c` (initiator user-signed PSBT path).

---

## Finding 1 — CRITICAL splice `tx_abort` after we signed

**Verdict: FIXED in `channeld`. PARTIAL in lightningd.**

Unpatched `check_tx_abort` at `0x458d` (`channeld.c:1873`) matches the AUDIT source. The loop xors `r13` to NULL (`inflight = NULL`), calls `have_i_signed_inflight(peer, r13)` at `0x4675`, then assigns `r13 = r15` (`inflight = itr`) at `0x4688`. Unpatched `have_i_signed_inflight` at `0x44f4` returns false on a NULL inflight (`channeld.c:1781-1782`). The guard never fires.

Patched `-O3` inlines `have_i_signed_inflight` into `check_tx_abort.part.0` at `0xad30` (`channeld.c:1926`). After a txid match the candidate is `%rbx = itr`, not a NULL pointer:

- `0xaebd`–`0xaf00`: compare `itr->outpoint.txid` (`*(%rbx)`) with the requested txid.
- `0xaf02`–`0xafd6`: walk `itr->psbt` at `+0x78` and call `psbt_input_have_signature`.
- `0xafe3`: `cmpb $0x0, 0xe0(%rbx)` — DWARF `i_sent_sigs`.
- `0xb01d`: `peer_failed_err` if either the PSBT signature or the flag is set.

The patched check is stronger than the one-line AUDIT fix (`have_i_signed_inflight(peer, itr)`). It tests the live PSBT *and* the persisted flag. `check_tx_abort.constprop.0` is the `txid == NULL` restart-without-delete path.

lightningd still deletes. Patched `handle_splice_abort` is inlined into `channel_msg` at `0x9fb90`. `fromwire_channeld_splice_abort` is `channel_control.c:341`. If the abort carries an outpoint, `wallet_inflight_del` runs at `0xa0067` (`channel_control.c:364`) with no load of `i_sent_sigs`. `tal_free` follows at `0xa006c`. Public HEAD still has the same shape (`AUDIT.md` quotes 346–362). Channeld refusing abort after sign is what stops the attack on a fully patched node. A mixed pair (new lightningd, old channeld) or any future path that delivers `splice_abort` with an outpoint after we signed still drops tracking.

Two supporting changes:

1. SQL `UPDATE channel_funding_inflights` now writes `i_sent_sigs` (unpatched UPDATE omitted it; only INSERT stored it). The patched `channeld` flag check survives a restart.
2. New `channel_watch_inflight_outs` at `0xe25c0` (`peer_control.c:2623`, 194 bytes) walks remaining inflights and calls `watch_txo(..., funding_spent)`. That is keep-watching, not a substitute for refusing delete. The symbol is absent from public HEAD.

Claim ID: `CLN-SPLICE-TXABORT-2026`. CWE-670 (always-incorrect control flow) plus CWE-162 (improper neutralization of input used for state). Impact: loss of channel funds in a 2-of-2 the victim no longer tracks. Fixed for the P2P path if both channeld and lightningd are v26.06.7. lightningd defense in depth remains open.

---

## Finding 2 — HIGH `s64` wrap on peer `update_add_htlc`

**Verdict: NOT FIXED.**

Patched `add_htlc` at `0x171a0` still compiles `full_channel.c:711-714`. Those lines in HEAD are the `sender == LOCAL` `chainparams->max_payment` gate. Peer amounts remain unrestricted. `handle_peer_add_htlc` is a 289-byte `.constprop.0` at `0x95f0`; the size jump `add_htlc` 2339→3440 and `channel_add_htlc` 201→492 is `-O3` inlining, not a new remote-amount check.

Patched `peer_accepted_htlc` grew 1166→1986. Extra DWARF lines 1346–1435 are inlined `calc_forwarding_channel` (HEAD 1354–1436), not an amount-vs-capacity gate. `check_fwd_amount` still exists and still requires `incoming >= outgoing`, which a `UINT64_MAX` inbound against a real onion amount passes.

`opening_common.c` DWARF max is 171 in the patched lightningd, equal to HEAD, which still sets `max_htlc_value_in_flight = AMOUNT_MSAT(UINT64_MAX)` at line 150. `amount_msat_greater(UINT64_MAX, UINT64_MAX)` remains false.

Public HEAD `full_channel.c` (1719 lines) still uses `s64` balances and `s64 -= u64` in `balance_add_htlc`. That is the wrap. It is still the public code, and the patched `add_htlc` still compiles the LOCAL-only payment cap.

Claim ID: `CLN-HTLC-S64-WRAP-2026`. CWE-190. Impact: accept a consensus-invalid commitment, then forward or fulfill real funds. `--offline` blocks new HTLCs. Still open on v26.06.7.

---

## Finding 3 — HIGH HSM / channeld splice signed blindly

**Verdict: NOT FIXED.**

`libhsmd.c` DWARF max is 2595 in both hsmd binaries, equal to HEAD. `handle_sign_splice_tx` still declares at line 1447. Unpatched ships a 279-byte standalone at `0x6015e`. Patched inlines it; the body is still “parse tx, derive funding key, `sign_tx_input` with `SIGHASH_ALL`, reply”. No new splice-validation strings appear in hsmd (`tx must have > 0 outputs` is generic wally).

HEAD `channeld.c:3858` still has the DTODO that splice must not take our funds. Patched `channeld.c` grew to 7226 lines; the new strings are STFU, resume, feerate, and `start_batch`, not “splice output does not match”. Combined with Finding 1, v26.06.7 stops the abort-after-sign theft. It does not add the HSM amount check the architecture needs.

Claim ID: `CLN-HSM-SPLICE-BLIND-2026`. CWE-345 (insufficient verification of data authenticity). Impact: any remaining `check_balances` hole is immediately signable. Still open.

---

## Finding 4 — MEDIUM `lowest_splice_amnt` field and slot swap

**Verdict: NOT FIXED.**

Patched `update_view_from_inflights` at `0x8a10` (`channeld.c:3798`, HEAD 3724):

- `0x8a6b`: `movq 0x68(%rsi), %rdx` — `inflight->amnt` (new total capacity), not `splice_amnt` at `+0x80`.
- `0x8a79`: `subq 0x80(%rsi), %rcx` — `splice_amnt` is used only to compute `remote_splice_amnt`.
- `0x8a90`: compare `%rdx` (`amnt`) with `view[REMOTE].lowest_splice_amnt[REMOTE]` at `+0x3a0`.
- `0x8a99`: write `%rdx` to `+0x398` (`view[REMOTE].lowest_splice_amnt[LOCAL]`).

That is the AUDIT swap: compare REMOTE/REMOTE, write REMOTE/LOCAL. Splice-out never drives `lowest_splice_amnt[LOCAL]` negative, so `get_room_above_reserve` will admit HTLCs that fit the old channel and not the pending splice.

Claim ID: `CLN-SPLICE-LOWEST-AMNT-2026`. CWE-682. Impact: HTLC vs pending splice-out race, not clean standalone theft. Still open.

---

## Finding 5 — MEDIUM splice `tx_signatures` overwrites inflight txid

**Verdict: FIXED** (clobber gone). Equality check vs inflight txid was not added next to the parse.

HEAD / unpatched `fromwire_tx_signatures(..., &inflight->outpoint.txid, ...)`. Patched `resume_splice_negotiation` at `0x11690`, `channeld.c:4043`:

```
11ca2: leaq 0xc0(%rsp), %rdx    ; stack local txid
11cc2: call fromwire_tx_signatures
```

Then `channeld.c:4052` tests `shared_input_signature`, `4058–4059` `tal_steal` witnesses into `inflight->psbt` at `+0x78`, `4066–4078` `psbt_input_set_signature`. The peer field no longer lands on `inflight->outpoint`. Dual-open’s `bitcoin_txid_eq` of the parsed txid against the inflight is still missing in the immediately following instructions. Witnesses still apply to our PSBT, so the peer cannot make us sign a different tx.

Claim ID: `CLN-SPLICE-TXSIGS-TXID-2026`. CWE-1287 (improper validation of specified type of input). Impact: state confusion with Finding 1; the write itself is gone in v26.06.7.

---

## Finding 6 — MEDIUM blinded-path fee numerator wrap

**Verdict: NOT FIXED.**

Patched lightningd still compiles `onion_decode.c:122-125` at `0x14d15a`–`0x14d1ab` (`ceil_div` of `(amt - fee_base) * 1000000`). File max is 464 vs HEAD 463. `amount_msat_sub_fee` exists as a string in hsmd/common and is unused on this path. No new overflow-check strings.

`check_fwd_amount` still blocks wrap-up payout (`incoming >= outgoing`). Wrap-down makes the node keep extra, not lose principal. The landmine remains if a later change special-cases blinded hops.

Claim ID: `CLN-ONION-BLINDED-FEE-WRAP-2026`. CWE-190. Related public fix `96f026ecc` only widened the denominator. Still open.

---

## Finding 7 — MEDIUM watchtower splice / HTLC gap

**Verdict: NOT FIXED.**

`penalty_tx_create` remains (`0x1db80`, 1102 bytes patched; 1198 unpatched). HEAD `watchtower.c` is 133 lines and only spends `to_them`. No new “penalty per splice” / “HTLC penalty” strings. HEAD `channeld.c:2553` still has the DTODO. Patched `channeld.c` growth is elsewhere (STFU / resume / feerate).

`--offline` does not fill this gap for a splice that already confirmed.

Claim ID: `CLN-WATCHTOWER-SPLICE-2026`. CWE-863. Impact: revoked splice or HTLC outputs unpenalized while the node is offline. Still open.

---

## Finding 8 — LOW–MEDIUM `INT64_MIN` / splice_locked raw `+=`

**Verdict: helper NOT FIXED. lightningd raw `+=` NOT FIXED. `-O3` may reject `INT64_MIN` by accident.**

Patched `amount_msat_add_sat_s64` at `0x1f2c0` still starts at `amount.c:403`. Negative path:

```
1f2c7: testq %rdx, %rdx
1f2ca: js    1f300
1f300: imulq $-0x3e8, %rdx, %r8
1f30c: negq  %rcx          ; -b
1f312: divq  %rcx          ; reverse-check of mul_overflows
```

HEAD source is still `amount_sat(-b)` with no `INT64_MIN` guard. The extra ~40 bytes vs unpatched are inlined `overflows.h`: `mulq $1000` + `jo` on the positive path, `imulq $-1000` / `negq` / `divq` on the negative path. `negq` of `INT64_MIN` leaves `0x8000...`; the reverse-check can fail and return false. That is an accidental reject, not an explicit fix.

Patched `channel_control.c` DWARF max is 2858, equal to HEAD, which still does:

```
channel->our_msat.millisatoshis += splice_amnt * 1000; /* Raw: splicing */
```

at 1197–1199.

Claim ID: `CLN-AMOUNT-INT64MIN-2026`. CWE-190 / CWE-682. Impact: crash or corrupt accounting on `opener_relative = INT64_MIN`, not demonstrated theft. Still open.

---

## Finding 9 — LOW simple-close output amount

**Verdict: the AUDIT file is not in these binaries. A cousin check was added for classic close, still without `our_msat`.**

Public HEAD `simple_close_control.c` (356 lines, `close_tx_check` at 35–90) landed after v26.06.6. Neither binary’s DWARF contains that CU. `option_simple_close` appears as a feature name in both.

Patched lightningd exports `close_tx_check` at `0xa61f0`, DWARF `closing_control.c:279` (HEAD that line is `towire_closingd_received_signature_reply`; they inserted into classic mutual close). Checks: `num_inputs == 1`, `wally_tx_input_spends` funding, every output script is local shutdown, remote shutdown, Elements fee, or (later in the function) a known script. Strings: `expected 1 input, got %zu`, `does not spend funding outpoint %s`, `output %zu goes to unknown script %s`, `output %zu has no script`. No compare of our output to `our_msat`.

AUDIT Finding 9 as stated (experimental simple close, missing `our_output >= our_msat`) is a HEAD-only gap. v26.06.7 added the shape check to classic close and still omitted the amount backstop.

Claim ID: `CLN-CLOSE-TX-AMOUNT-2026`. CWE-1284. Impact: missing backstop; current closer math is supposed to prevent theft. Amount check still absent.

---

## Finding 10 — LOW interactive-tx ignores `channel_id`

**Verdict: NOT FIXED.**

`interactivetx.c` DWARF max is 859 in both channeld binaries, equal to HEAD. Dual-open still checks `cid` (`dualopend.c`); splice `channeld` is one channel per process. Spec sloppiness, not cross-channel theft.

Claim ID: `CLN-INTERACTIVETX-CID-2026`. CWE-345. Still open.

---

## Extra changes in v26.06.7 (not in AUDIT.md)

These are patched-only strings or symbols. They look like splice/open hardening around the Finding 1 work, not new fund-loss bugs found from the binary.

| Change | Where | Reading |
|---|---|---|
| `Cannot resume splice that we havent started` | channeld | resume path refuses a splice we never initiated |
| `Double STFU issue detected` | channeld | second `stfu` while already quiet |
| `STFU mode timed out.` / `stfu_did_timeout` (34 B) | channeld | STFU no longer hangs forever |
| `Invalid next_revocation_number value` | channeld | reestablish / revoke sanity |
| `Don't send a start_batch with batch sizebelow 2` | channeld | BOLT message-batch floor (missing space in the format string) |
| splice feerate min **and** max | channeld | replaces unpatched “too low” only |
| `Rejecting open_channel2 %s: too many inflight opens` / `Too many inflight channel opens (max %u)` | lightningd | dual-open inflight cap |
| `Can't calculate the next feerate...` | lightningd / dualopend | replaces an overflow-flavored string |
| `channel_watch_inflight_outs` | lightningd `peer_control.c:2623` | watch every inflight funding outpoint |
| `i_sent_sigs` on SQL UPDATE | lightningd wallet | persist Finding 1’s flag |
| `close_tx_check` | lightningd `closing_control.c:279` | classic mutual close shape |
| `FUNDS LOSS of %s: peer took funds onchain with preimage, but we already failed the incoming HTLC` | lightningd | onchain/HTLC accounting log, not a splice fix |
| `onchaind_restart` / `Chain reorganization: did not restart onchaind` | lightningd | reorg handling |

`dualopend.c` +105 lines vs HEAD is the largest embargoed CU after `channeld.c` and `peer_control.c`. Treat that as dual-open feerate / inflight-open policy, not as a silent fix of Findings 2–4.

---

## Public-source bugs still present (model-score extras)

These are in HEAD `c1551c557` and, by DWARF, in the patched binaries. They were not discovered from the binary; they are public knowledge that v26.06.7 left standing.

1. `full_channel.c` `s64` balances and LOCAL-only `max_payment` (Finding 2).
2. `max_htlc_value_in_flight` default `UINT64_MAX` (`opening_common.c:150`).
3. `commit_tx.c:151-153` asserts `to_local + to_remote <= funding` and omits HTLC outputs (companion to Finding 2).
4. `hsmd` `handle_sign_splice_tx` has no output/amount checks (Finding 3).
5. `channeld.c:3858` DTODO: splice tx not validated before `hsmd_sign_splice_tx`.
6. `update_view_from_inflights` uses `inflight->amnt` and swapped REMOTE slots (Finding 4).
7. `onion_decode.c:119-123` `ceil_div` numerator wrap; `amount_msat_sub_fee` unused (Finding 6).
8. `watchtower.c` penalty spends only `to_them`; DTODO at `channeld.c:2553` (Finding 7).
9. `amount_msat_add_sat_s64` negates `s64` blindly; lightningd splice_locked raw `+= splice_amnt * 1000` (Finding 8).
10. `interactivetx.c` parses `cid` and never checks it (Finding 10).
11. Other splice DTODOs still in HEAD: shutdown-vs-splice rules (`channeld.c:895`, `2792`), HTLC sig vs rotated funding key (`2221`), reserve (`3685`, `5048`), locktime (`4338`).

---

## Claims for later OpenTimeStamps (do not mint CVE-IDs here)

Stable IDs for a later OTS commit. Status is relative to **v26.06.7**. Public HEAD still contains every `open` row.

| Claim ID | CWE | Severity | v26.06.7 | One-line |
|---|---|---|---|---|
| `CLN-SPLICE-TXABORT-2026` | 670 | CRITICAL | **fixed in channeld**; lightningd delete still unguarded | `have_i_signed_inflight(peer, NULL)` let `tx_abort` drop a signed splice |
| `CLN-HTLC-S64-WRAP-2026` | 190 | HIGH | **open** | peer `amount_msat = UINT64_MAX` wraps `s64` remote balance |
| `CLN-HSM-SPLICE-BLIND-2026` | 345 | HIGH | **open** | hsmd signs splice funding input with no output/amount check |
| `CLN-SPLICE-LOWEST-AMNT-2026` | 682 | MEDIUM | **open** | `lowest_splice_amnt` reads total funding and writes the wrong side |
| `CLN-SPLICE-TXSIGS-TXID-2026` | 1287 | MEDIUM | **fixed** | `fromwire_tx_signatures` wrote the peer txid into `inflight->outpoint` |
| `CLN-ONION-BLINDED-FEE-WRAP-2026` | 190 | MEDIUM | **open** | blinded `payment_relay` numerator wraps in `ceil_div` |
| `CLN-WATCHTOWER-SPLICE-2026` | 863 | MEDIUM | **open** | watchtower penalty is `to_them` only; no per-splice / HTLC penalty |
| `CLN-AMOUNT-INT64MIN-2026` | 190 | LOW–MEDIUM | **open** | `amount_sat(-b)` on `INT64_MIN`; splice_locked raw `+=` |
| `CLN-CLOSE-TX-AMOUNT-2026` | 1284 | LOW | **open** (shape check added on classic close) | close tx not required to pay us `our_msat` |
| `CLN-INTERACTIVETX-CID-2026` | 345 | LOW | **open** | interactive-tx ignores parsed `channel_id` |

---

## Feasibility of AI binary analysis on this pair

**What worked.** Unstripped `-g` ELF plus a public sibling tree is enough to score known bugs. The winning loop was: (1) string and symbol diff to see *that* splice/STFU/SQL changed, (2) DWARF struct offsets as a ruler, (3) `objdump -d -l` on the named function, (4) HEAD source to interpret the same line numbers. Finding 1’s NULL-pointer call is visible in unpatched `-Og` as a two-instruction sequence (`xor r13d; call have_i_signed`). Finding 4 is a single `movq 0x68(%rsi)` vs `0x80`. Finding 5 is `leaq 0xc0(%rsp), %rdx` instead of `&inflight->outpoint.txid`. Finding 6 is DWARF still pointing at `onion_decode.c:122`.

**What got in the way.** The patched build is `-O3` and the unpatched build is `-Og`. `have_i_signed_inflight` disappears as a global. `handle_splice_abort` and `handle_sign_splice_tx` inline into parents. Function sizes jump thousands of bytes with no source change (`add_htlc` 2339→3440). A naive “this symbol grew, so they fixed it” score would mark Finding 2 fixed. It is not. Always recover the *line* and the *field offset*, not the byte count.

**What DWARF still gives under `-O3`.** Line numbers survive inlining well enough to map `check_tx_abort.part.0` back to `channeld.c:1938` and the `i_sent_sigs` compare to `+0xe0`. Producer strings document `-Og` vs `-O3` so the analyst can expect `.cold` noise. `struct inflight` member locations are intact.

**What this setup does not test.** A stripped `-O3` release without DWARF would drop Findings 4 and 5 from “high confidence” to “guess from strings”. Finding 1 would still be reachable from the new `i_sent_sigs` SQL and the `peer_failed_err` after a txid match, but the NULL-pointer story would be gone. No decompiler (Ghidra/r2) was used; llvm `objdump` plus pyelftools were enough because debug info was present.

**Benchmark reading.** Given the known bug list, grok-4.6 verified 10/10 findings against the binary: 2 fixed, 1 partial, 7 unfixed (Finding 9 restated as a cousin). Extra public-source items 1–11 above are HEAD-confirmed, not binary-discovered. The embargoed v26.06.7 work is concentrated on splice abort, inflight watches, STFU, feerate bounds, dual-open inflight caps, and classic-close shape — consistent with a 14-day point release aimed at Finding 1, not a sweep of the audit.

---

## What this report does not claim

No binary was executed. No peer was connected. No transaction was broadcast. `--offline` was not runtime-tested. CVE numbers were not assigned. The patched source was not reconstructed beyond the DWARF line map and the new strings. Other architectures and the debuginfo-less tarball were not compared.

Until Findings 2 and 3 are patched, `--offline` (do not listen, do not reconnect) is still the right operational mitigation for a node that must keep its existing channels. It does not recover a splice that was already signed and aborted on v26.06.6, and it does not fill the watchtower splice gap.
