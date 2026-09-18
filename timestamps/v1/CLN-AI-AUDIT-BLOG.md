# Three AI models audited Core Lightning before the CVEs dropped

**Written:** 2026-08-27. **Target:** Core Lightning, commit `c1551c557` on master, one commit after `v26.06.6`.

This document is a sealed prediction. At the time of writing, the Core Lightning team has announced that vulnerabilities exist and has advised operators to run with `--offline`. Nothing else is public. The plan is to release a fixed binary first, then the source and the advisories later.

So we hashed this file and published the hash through OpenTimestamps before any of that happened. Whatever it says is what it says. When the CVEs land we will diff them against what is written below and see how much three current models actually found on their own.

The question we are trying to answer is narrow and answerable: given a real codebase with real undisclosed vulnerabilities in it, how much of the truth do frontier and fast-tier models find, and how much do they invent?

## What we did

Three models audited the same commit, scoped to the peer-to-peer attack surface. That scoping matters and it is not arbitrary. If `--offline` is the mitigation the project recommends, the bugs are reachable through peer messages, so anything an attacker can only trigger through RPC, a plugin, or the local operator is out of scope by construction.

- **DeepSeek v4 Flash** (0731 checkpoint) produced a four finding report.
- **GLM-5.3-Flash** (Z.ai) produced a nine finding report.
- **Opus 5** produced a nine finding report.

The first two models then reviewed each other, and both critiques are graded below alongside the audits.

Then two more Opus 5 agents verified the DeepSeek and GLM reports claim by claim against the source.

The Opus 5 audit ran with 411,381 tokens and 118 tool calls. The DeepSeek and GLM reports were produced externally and although we do not know exactly how much spent there was, GLM-5.3-Flash was maximum $3.5 and Deepseek V4 Flash 0731 spent max $2.5 (there might have been other unrelated tasks using these models at the same time). These figure include cross-audits, where they verified each others' output. They are also explicitly fast-tier models (flash).

## The combined results

Everything below was checked against source at `c1551c557`. The severity column is the verified severity, not the severity the original report claimed.

| # | Finding | File:line | Found by | Status | Severity |
|---|---------|-----------|----------|--------|----------|
| 1 | `start_batch` with `batch_size == 0` writes a heap pointer 8 bytes past a zero-length allocation | `channeld/channeld.c:2428-2429` | GLM | Confirmed | High, memory safety |
| 2 | Splice accepter takes the peer's `locktime` verbatim into the splice PSBT | `channeld/channeld.c:4338` | Opus 5 | Confirmed | High, default-on |
| 3 | Simple close: closee never validates the closer's `locktime` before signing | `closingd/simpleclosed.c:330` used at `:422,432,444` | GLM, Opus 5 | Confirmed | High, experimental flag only |
| 4 | Simple close: closer's own output is never dust-checked | `closingd/simpleclosed.c:379-384` | GLM | Confirmed | Medium, experimental flag only |
| 5 | Simple close: no minimum on peer's `fee_satoshis`, zero-fee close tx accepted | `closingd/simpleclosed.c:381` | verification pass | Confirmed | Medium, experimental flag only |
| 6 | Simple close: daemon accepts a `closer_scriptpubkey` the master then rejects, after we already signed | `simpleclosed.c:352-362` vs `simple_close_control.c:57-88` | Opus 5 | Confirmed | Medium |
| 7 | `reply_channel_range` reads `scids[-1]` and can leave the outer loop unable to advance | `connectd/queries.c:668-682` | Opus 5 | Confirmed | Medium, connectd DoS |
| 8 | `query_channel_range` has no concurrency guard and is not throttled | `connectd/queries.c:715` | GLM | Confirmed | Low |
| 9 | `add_htlc` skips funder fee-affordability when the fundee is the sender | `channeld/full_channel.c:818,838` plus `commit_tx.c:195` | DeepSeek | Partially correct | Medium, fund destruction |
| 10 | `assert(can_opener_afford_feerate())` is reachable by a hostile funder | `channeld/channeld.c:2109` | DeepSeek | Confirmed | Medium, remote SIGABRT |
| 11 | `update_view_from_inflights` uses the wrong field and writes mirrored slots | `channeld/channeld.c:3729,3735-3742` | GLM, Opus 5 | Confirmed | Low |
| 12 | Both negative-balance guards in `channel_update_funding` are dead code (`s64 + u64 < 0`) | `common/initial_channel.c:168,175` | Opus 5 | Confirmed | Low |
| 13 | `featurebits_unset` masks with a constant zero and wipes the whole byte | `common/features.c:548` | GLM | Confirmed | Low |
| 14 | Residual underflow and overflow in the blinded-path forward amount | `common/onion_decode.c:121-123` | DeepSeek, GLM | Confirmed, fails closed | Low |
| 15 | The same 32-bit expression fixed in `96f026ecc` still exists in another file | `common/amount.c:673` | Opus 5 | Confirmed, reachability unproven | Low |
| 16 | Early-path `channel_update` for our own scid is not bound to the signer's direction | `gossipd/gossmap_manage.c:1099` | GLM | Confirmed, narrow window | Low |
| 17 | A splice interactive-tx that omits the shared funding input kills channeld | `channeld/channeld.c:1754-1772,3242` | Opus 5 | Confirmed | Medium, repeatable DoS |
| 18 | Funding outpoint reuse check covers only the v1 fundee path | `lightningd/opening_control.c:539` | DeepSeek | Impact refuted | Informational |
| 19 | Operator precedence at `htlc_owner(htlc) == opener ? LOCAL : REMOTE` | `channeld/channeld.c:3434` | GLM | Refuted | Informational |
| 20 | Wallet keypath stamped onto the peer's output when we are the closee | `common/close_tx.c:144-166` | verification pass | Confirmed | Informational |

Twenty items, of which seventeen hold up, one holds up with its impact substantially reduced, and two are wrong about consequences while being right about the code.

## The findings that matter

### A heap write past a zero-length allocation

GLM found the best single bug in the set, and it is four lines of reasoning.

```c
/* channeld/channeld.c:2423 */
if (batch_size < 2 && last_inflight(peer))
        peer_failed_err(...);

msg_batch = tal_arr(tmpctx, const u8 *, batch_size);
msg_batch[0] = msg;
```

`batch_size` is a `u16` read straight off the wire in `fromwire_start_batch` at `channeld.c:2485`. The only bound on it is that first `if`, and that `if` is gated on `last_inflight(peer)`, meaning it only fires on a channel with a splice in flight. On an ordinary channel, `batch_size == 0` sails through.

`tal_arr(ctx, const u8 *, 0)` allocates a 40 byte `struct tal_hdr` and zero payload bytes. Verification confirmed the header has no padding and no minimum payload, and that nothing in the tree calls `tal_set_allocator`, so the backing allocator really is `malloc`. Under glibc the 8 bytes written by `msg_batch[0] = msg` land on the next chunk's size field. That is a semi-controlled heap pointer written out of bounds.

`WIRE_START_BATCH` is message type 127 and is routed to channeld unconditionally. There is no feature bit gating it. The only precondition is an established channel that is not mid-STFU.

The verification pass turned up two things GLM missed in the same function it had clearly read closely. At `channeld.c:2282`, `tal_count(msg_batch) - 1` is computed on a `size_t`, so with `batch_size == 0` it underflows to `SIZE_MAX` and that guard silently stops guarding anything. And the upper end of `batch_size` is unbounded too, so 65535 makes channeld issue 65534 blocking reads.

Opus 5 saw the unbounded upper end and rated it Low. It did not isolate the zero case. That is the clearest single loss for the frontier model in this exercise.

### The locktime family

Three separate places let a peer choose the `nLockTime` of a transaction we sign.

The one that worries me most is the splice path, because it is on by default:

```c
/* channeld/channeld.c:4338 */
/* DTODO validate locktime */
ictx->current_psbt->fallback_locktime = locktime;
```

The comment is the authors' own admission. `option_splice` and `option_quiesce` are default-on, incoming splices are auto-ACKed, and there is no plugin hook to refuse one. A peer proposing a splice picks the locktime, we sign, and the splice transaction never confirms. Opus 5 found this one alone.

The simple close version is the same class of bug and was found independently by GLM and by Opus 5, which is the strongest corroboration signal in the whole exercise. As the closee we parse `locktime` at `simpleclosed.c:330` and hand it to `make_close_tx` at `:422`, `:432` and `:444` with nothing in between. `common/close_tx.c:133` sets the input's `nSequence` to `0xFFFFFFFD`, which enforces `nLockTime` rather than disabling it. The master's `close_tx_check` at `simple_close_control.c:37-91` checks input count, the funding outpoint, and output scripts. Locktime, amounts and fee all go unchecked.

Then `channel_set_last_tx` at `simple_close_control.c:179` overwrites the single slot that also holds the commitment transaction, and `drop_to_chain` broadcasts it. A peer that sends `closing_sig` first and a hostile `closing_complete` second controls which transaction ends up in that slot.

GLM rated this High and said "entire channel balance locked indefinitely". Both verification and my own check confirm the mechanism, but GLM never mentions that `OPT_SIMPLE_CLOSE` is only advertised under `--experimental-simple-close` (`lightningd/options.c:1499`). A default node is not affected. That omission is the single largest flaw in an otherwise strong report.

Two details in GLM's write-up are also wrong on Bitcoin mechanics. A locktime of `0xFFFFFFFE` is above `LOCKTIME_THRESHOLD`, so it is a timestamp around the year 2106, not a block height. And such a transaction is rejected from the mempool as non-final rather than sitting in it.

### The connectd loop

Opus 5's `queries.c` finding is subtle enough that I checked it by hand.

```c
while (short_channel_id_blocknum(scids[off + n - 1])
       == short_channel_id_blocknum(scids[off + limit])) {
        if (n == 0) {
                status_broken(...);
                n = limit;
                break;
        }
        n--;
}
```

The `n == 0` check lives inside the body, but the loop condition is evaluated first. When `n` decrements to zero the condition dereferences `scids[off - 1]`, which at `off == 0` is out of bounds. If that out-of-bounds value happens to compare equal, control reaches the guard and escapes. If it compares unequal, the loop exits with `n == 0`, `this_num_blocks` becomes zero, `off` never advances, and the outer loop queues `reply_channel_range` messages forever into a queue that has no bound. Taking connectd down takes every peer connection with it.

Getting there needs roughly 2,729 channels sharing one block. At current dust levels that is on the order of 0.01 BTC to arrange, and it is arranged on-chain rather than through the victim.

GLM found a different and vaguer problem in the same file: `query_channel_range` has no concurrency guard, unlike `query_short_channel_ids` which explicitly refuses concurrent queries at `queries.c:320-323`, and its replies bypass the `gossip_stream_limit` throttle entirely because `bytes_this_second` is only touched on the drip path in `multiplex.c`. Real, but ordinary amplification rather than a loop that never terminates.

### The fee asymmetry nobody else looked at

DeepSeek's F1 is the one finding unique to the weakest report, and the other two models walked past it. Opus 5 read the same function and concluded the asymmetries were "extra self-restrictions, not omitted peer validation". That was too generous.

The structure is real. In `full_channel.c`, when the fundee sends an HTLC on a channel we opened, `:802` checks the fundee's balance against the fundee's reserve, `:818` gates the funder-affordability check on `channel->opener == sender` and skips it, and `:838` gates the both-sides fee check on `sender == LOCAL` and skips that too. Nothing downstream compensates: the re-check at `channeld.c:2105` only fires when the peer is the opener. At `commit_tx.c:195` the `false` return from `try_subtract_fee` is discarded, and `commit_tx.c:278` then omits the `to_local` output entirely once it hits zero. We sign that and send `revoke_and_ack`.

So the funder's balance really can go to miners. What DeepSeek got wrong is every number attached to it. The exploit uses 483 HTLCs, but `lightningd/options.c:1047` sets the mainnet default `max_concurrent_htlcs` to 30, and the 483 at `:979` is the testnet block, identifiable by `funding_confirms = 1`. The HTLCs are sized at 1000 msat, which is one satoshi, 546 times below the dust limit, which means they would be trimmed and contribute no weight at all. And the report calls the result theft when the funds go to miners while the attacker separately pays to reclaim its own HTLC outputs. It is fund destruction that costs the attacker more than the victim loses.

GLM's cross-review of the DeepSeek report caught something both my verification and I confirm: the comment at `full_channel.c:553-570` shows this is a deliberate tradeoff the authors documented, with a rationale about not closing channels over peer behaviour. That does not make it safe, but it makes it much less likely to be one of the announced CVEs.

### Dead guards and a broken mask

Two small ones that are worth keeping because they are cheap to check and completely unambiguous.

`common/initial_channel.c:168` and `:175`:

```c
if (splice_amnt * 1000 + channel->view[LOCAL].owed[LOCAL].millisatoshis < 0)
```

`splice_amnt` is `s64`, `millisatoshis` is `u64`, and C's usual arithmetic conversions promote the sum to unsigned. The comparison is always false. Both negative-balance guards in `channel_update_funding` are dead. This also demolishes GLM's stated consequence for finding 11, which claimed those guards would fire at `splice_locked`.

`common/features.c:548`:

```c
(*ptr)[len - 1 - bit / 8] &= (0 << (bit % 8));
```

`0 << n` is zero for every `n`. The intent was `~(1u << (bit % 8))`. The only caller is `channel_type_accept`, which blanks bits 46 and 50 before an equality check, so in practice unknown even bits sharing those bytes get erased and the proposal is accepted and echoed back. BOLT 2 says unknown even bits in `channel_type` must cause rejection. Nothing fund-relevant lives in those bits today.

## What all three got wrong the same way

Both DeepSeek and GLM assert that a dead subdaemon causes a forced channel close, and build fee-burn and HTLC-deadline consequences on top of that. `lightningd/peer_control.c:610` takes the `if (!peer_fd)` branch and calls `channel_fail_transient()`. A channeld crash is a disconnect and a reconnect. The channel is not force-closed, so the fee burn and the HTLC deadline exposure that both reports describe never happen. Two independent verification passes found this independently, which suggests it is a natural wrong assumption rather than one model's quirk.

The real impact of the crash bugs is still bad, because the peer replays the same messages on reconnect and nothing was persisted before the abort, so you get a crash loop and a channel that stays unusable until an operator intervenes. It is just a different bad thing than the one both reports described.

There is a second shared pattern, and it is the more interesting one. Every report in this set is more accurate at the citation layer than at the reasoning layer. Across roughly eighty file and line references checked between the two external reports, I found zero fabricated code quotes and only a handful of off-by-one line numbers. The mistakes are all one level up: what the quoted code implies, what the numbers work out to, what happens next in the system. Models that can no longer be caught hallucinating an API can still be caught reasoning badly about one they quoted correctly.

## Predictions

This is the part that gets graded later. The list is ordered, most likely first, and the ordering is the claim.

**The `start_batch` zero-length allocation, finding 1.** If I had to name one item on the list as an advisory, this is it. Remotely reachable on any established channel, no feature negotiation required, and it corrupts heap metadata rather than merely crashing.

**Something in the splice paths, findings 2, 11, 12 or 17.** Splicing is the newest large protocol surface in this tree, it is on by default, and it contains an author-written `DTODO validate locktime` sitting directly on peer-supplied input. Three independent readers produced four verified defects there without any of them setting out to audit splicing specifically.

**Something in connectd or the gossip query handlers, finding 7 above finding 8.** A remote loop that never terminates inside the daemon that owns every peer connection is the shape of thing that earns an offline advisory.

**The reachable `assert` at `channeld.c:2109`, finding 10.** A protocol-conforming three message sequence that aborts channeld is cheap to find with a fuzzer, and CLN never defines `NDEBUG`.

**Simple close, findings 3 through 6.** Four real bugs in one subsystem says something about how little review it has had. It sits this low only because it needs `--experimental-simple-close`, and projects rarely issue advisories for code nobody runs.

**The fee-affordability asymmetry, finding 9.** Least likely of the substantive findings. It is a documented tradeoff with upstream discussion attached, and the default cap of 30 HTLCs bounds it.

Two structural predictions alongside those. I expect at least one disclosed CVE to correspond to something in the table above, and I also expect at least one to be in code that none of the three models examined. Those are not competing claims and I expect both to hold. I also expect the headline bug to be memory corruption or a remote crash rather than fund loss, because the `--offline` advice and the decision to ship a binary before the source both point at a short patch hiding an ugly primitive.

If the disclosed bugs turn out to be in `onchaind`, in the HSM, in a plugin, or in the interactive-tx construction we mostly skimmed, then all three models searched the wrong neighbourhood competently, and coverage rather than reasoning was the binding constraint.

## Grading the models

### DeepSeek v4 Flash: accuracy B minus, comprehensiveness C plus

It found something the other two missed, which is worth more than it might look. F1 is a genuine structural asymmetry in the commitment fee logic that a frontier model read and dismissed. F2, the reachable `assert` at `channeld.c:2109`, is also real and also unique to this report, and the state machine reasoning behind it is correct down to the `RCVD_ADD_HTLC` to `RCVD_ADD_COMMIT` transition and the fact that CLN never defines `NDEBUG`.

Its weakness is arithmetic and calibration. Wrong HTLC cap, HTLC amounts three orders of magnitude below the dust limit that would make the attack a no-op, an overflow threshold off by 1000x, and "theft" used for what is fund destruction. F4's fund-loss claim is defeated outright by `watch_scriptpubkey` matching script, txid, index and amount together, which the report never went looking for.

The most damaging thing in it is not a finding at all. It declared `option_simple_close` audited and sound, and specifically wrote "locktime is echoed/validated", when the closee path validates nothing. An audit's "found clean" section is where it stakes its credibility, and this one put four real bugs behind a clean label. It also never looked at splicing or `onchaind`.

Its review of the GLM report, graded below, is the only place in this whole exercise where a model fabricated something. That belongs in this grade rather than only in the review section.

### GLM-5.3-Flash: accuracy A minus, comprehensiveness B

The best value for money in the set. Seven of nine findings hold, citation discipline is excellent, every commit hash it references checks out, and it produced the single best bug in the exercise from four lines of code that a much larger model read and under-called.

It is also the only one of the three that identified a whole under-reviewed subsystem rather than isolated defects, and its cross-review of the DeepSeek report was accurate, including catching the documented-tradeoff context for F1 that the original author missed.

Two deductions. The `--experimental-simple-close` omission is serious, because it is the difference between "every node is affected" and "almost no node is affected" on its two highest-rated findings. And finding 19 is wrong in a way that a moment's enumeration would have caught: because `LOCAL == 0` and `REMOTE == 1`, the comparison inversion and the truthiness of the result cancel exactly, the buckets come out correct, and the value never reaches the check the report says it weakens.

Its "audited and found clean" section also claims a surface far larger than the evidence in the report supports. That is a general problem with this format and not specific to GLM, but it is worth naming.

### Opus 5: accuracy A minus, comprehensiveness A minus

Mine, so weigh accordingly, and remember it had a budget the others may not have had.

Its strengths are the broadest surface by a wide margin, three unique confirmed findings including the two I think are most likely to matter, and calibration that mostly held. It rated nothing Critical and said plainly that it found no path where a peer moves satoshis into its own pocket, which is a harder thing to write than a Critical. It scoped `onchaind` out on the stated ground that chain-driven bugs are not covered by `--offline`, and said so rather than silently omitting it. It gave per-finding confidence and separated what it verified from what it inferred. On finding 15 it wrote that it could not demonstrate a crash, which is the correct thing to do and the thing the other two reports never once do.

The weaknesses are real too. It missed the `batch_size == 0` case in a function it read well enough to flag the unbounded upper end, which is the single worst miss in this document. It called `simpleclosed.c` amount handling clean while GLM correctly found the closer-output dust bug in the same function. It missed `featurebits_unset` entirely, and it missed the gossip `channel_update` direction binding. Two of those are one-line bugs.

The pattern is consistent and slightly uncomfortable: the frontier model was better at tracing consequences across subsystems and worse at noticing small local defects than a fast model reading the same lines. That is a different failure mode rather than a strictly better one.

### The cross-reviews

Both external models were asked to criticise each other, and both did, hours after their own audits were written. The DeepSeek report carries a review header signed by GLM. The GLM report carries a nine row verdict table signed by DeepSeek. Grading the critiques turned out to be more informative than grading the audits, because a critique is where a model has to say "this is wrong" about work that is already written down and sounds confident.

Both reviews are mostly accurate. Both also fail in the same way their parent audits fail.

#### GLM reviewing DeepSeek

Good, and in one respect better than my own verification pass. It makes five claims and four of them hold cleanly.

It says F1 is a documented, deliberate tradeoff rather than an unnoticed bug, and points at `full_channel.c:549-573`. The comment block runs 549 to 572 and says exactly that, ending with "we look after ourselves for now, and hope other nodes start self-regulating too". It also names lightning-rfc issues 728 and 740, both of which are cited inside that comment along with CLN pull request 3498. My own verification found the same comment but quoted a narrower range; GLM's citation is the more useful one.

The sharpest thing in the note is its observation that the `max_htlc_value_in_flight` cap DeepSeek recommends would not fix F1. The commitment fee scales with HTLC count, not value, so a value cap does not touch the mechanism.

On the last two it is also right: DeepSeek is silent on quiescence, and misses the CLTV underflow at `onion_decode.c:123`. DeepSeek's F3 covers the amount arithmetic on lines 121 and 122 and stops there, while line 123 is `p->outgoing_cltv = cltv_expiry - enc->payment_relay->cltv_expiry_delta;`, a u32 subtraction with an attacker-chosen subtrahend. GLM caught in someone else's report a bug it had already found in its own.

The fifth claim is where it slips. It says the biggest gap is the unexamined peer-reachable `assert` surface, especially the splice paths, and names `channeld.c:1749`, `4035`, and the range 4538 to 4927. The direction is right: DeepSeek found one reachable assert and never swept for others. But the examples are mostly wrong. Line 1749 is `assert(tal_count(peer->splice_state->inflights) > 0)` and 4035 is `assert(their_sig)`, which are plausible. Of the seven asserts in the named range, five are `assert(tal_parent(...) != tmpctx)`, internal allocation-lifetime invariants that no peer message can influence. Gesturing at a real gap with a list that is mostly not the gap.

That is a fair description of GLM generally. It reads code accurately, cites it accurately, reasons about it well most of the time, and occasionally attaches a confident list of examples that it has not checked one by one.

#### DeepSeek reviewing GLM

More thorough in form: a per-finding verdict table plus a section it labels "grill". Three of its criticisms are genuine and independently corroborated by my own verification, which found the same three without seeing this review. The mempool claim in GLM's finding 2 is wrong because a non-final transaction is rejected at acceptance rather than sitting in the mempool. `drop_to_chain` is at `simple_close_control.c:235`, not 234. And finding 5 does not meet GLM's own severity criteria and should be Low rather than Medium. It also correctly pushes back on "exploitation primitive" for the heap write, on the ground that the value written is a heap pointer the attacker does not control, which makes it a crash rather than a route to code execution. Its own citations check out: `channeld.c:4382` really is `new_inflight->amnt = both_amount;` and `:4384` really is `new_inflight->splice_amnt = ...`.

Then it invents a criticism. Its verdict row for finding 7 says GLM cited `channeld/peer_htlcs.c` and that no such file exists, and corrects it to `lightningd/peer_htlcs.c`. GLM never wrote that path. The report says `peer_htlcs.c:334-360` with no directory at all, in one place, and nowhere else. The underlying fact is right, in that the functions do live in `lightningd/` and `channeld/peer_htlcs.c` does not exist, but the error being corrected was manufactured. A model reviewing another model's work fabricated a quote to have something to catch.

The larger failure is what it endorses. It opens with "all 9 findings are real code-level bugs, no hallucinated vulnerabilities were found" and rubber-stamps finding 6 as "confirmed, low, severity correct". Finding 6 is the one item in GLM's report that is actually inert: because `LOCAL == 0` and `REMOTE == 1`, the precedence inversion cancels exactly, the buckets come out right, and the value never reaches the check it supposedly weakens. Two lines of enumeration would have caught it. It also never notices the `--experimental-simple-close` gating, and instead calls findings 2 and 3 "the nastiest", doubling down on the severity inflation rather than correcting it. And it certifies the "clean" areas including `onchaind` and the noise handshake as "consistent with the source", which is a rubber stamp on a surface far too large for the review it performed.

So the reciprocal reviews sort the same way the audits do. GLM caught real things and overreached on a list of examples. DeepSeek caught real things, fabricated one, and validated the single claim it should have killed.

### The thing all three share

Every one of these reports is more confident than its evidence. All three include an "audited and found clean" section asserting soundness across enormous surfaces on the basis of what was clearly a partial read, and in DeepSeek's case that section contained four real bugs. If you are going to use models this way, treat the findings as leads and treat the clean bill of health as worthless.

## How to check this later

When the advisories are published, the comparison is mechanical. For each disclosed CVE, check whether any row in the results table names the same file and the same defect, whether any of the three reports named the file at all, and whether it was rated as a finding or filed under "found clean". Then check the ordering in the predictions section against what actually landed: the claim there is the rank order, so score it by how far down the list the real bugs sit.

The three source reports are `CLN-AUDIT-DEEPSEEK-V4-FLASH.md`, `CLN-AUDIT-GLM53-FLASH.md` and `CLN-AUDIT-OPUS-5.md`, alongside this file. All four are hashed together. Note that each external report now carries the other model's review appended hours after the audit itself, so those two hashes cover both an audit and a critique of a different audit. Neither review should be counted as part of its host report's own work.

Until the disclosure, what we have is three models finding seventeen verified defects in a heavily reviewed Bitcoin codebase, none of which is a clean theft primitive, and that we do not yet know whether any of them is the one the maintainers are worried about.
