# Core Lightning (CLN) audit report — peer-to-peer fund-loss vulnerability

- Repo audited: `/home/juraj/tmp/lightning`, upstream `master` @ `c1551c557` (2026-08-24), tag base `v26.06.6`
- Auditor: opencode + qwen3-8-24b (model id `venice/qwen-3-8-27b`)
- Date: 2026-08-28
- Verdict: **1 significant vulnerability found in peer-to-peer code that can lead to loss of funds** (plus one minor secondary note at the end).

```
BUG:   lightningd/simple_close_control.c — simple_close close transaction
       accepted without checking that it actually pays us; a transaction
       crafted by the remote peer is then signed by us, saved to the DB as
       the canonical channel close tx ("last_tx") and used for broadcast /
       wallet bookkeeping.
IMPACT: loss of funds / channel closed on attacker-chosen terms
FEEDBACK: https://github.com/ElementsProject/lightning/pull/9417 (open fix)
```

---

## Vulnerability: `option_simple_close` — mutual-close tx accepted without a "pays us enough" check and stored peer-controlled tx becomes canonical (`last_tx`)

**Component:** `experimental-simple-close` feature (`OPT_SIMPLE_CLOSE`, feature bits 60/61),
master side of the close:

- `lightningd/simple_close_control.c` (`close_tx_check()`, `handle_simpleclosed_got_sig()`, `handle_simpleclosed_closee_broadcast()`, `handle_simpleclosed_complete()`)
- `closingd/simpleclosed.c` (`handle_closing_complete()`, `handle_closing_sig()`)
- `common/close_tx.c` (`create_simple_close_tx()`)
- `lightningd/peer_control.c` (`sign_and_send_last()` / `drop_to_chain()` — consume `channel->last_tx`)

**Requires:** the node running with `--experimental-simple-close` (feature bit 60/61 negotiated with the remote peer) and a mutual (`close`) of a channel. Fully reachable from a remote peer — nothing triggers with `--offline`, consistent with the given hint.

```c
// lightningd/simple_close_control.c:37 — close_tx_check()
/* Check that tx spends exactly our funding outpoint and every output goes
 * to a known shutdown script.  Returns an error string, or NULL on success. */
static const char *close_tx_check(const tal_t *ctx,
				   const struct channel *channel,
				   const struct bitcoin_tx *tx)
{
	if (tx->wtx->num_inputs != 1) ...
	if (!wally_tx_input_spends(&tx->wtx->inputs[0], &channel->funding)) ...
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		...
		if (scripteq(script, channel->shutdown_scriptpubkey[LOCAL]))
			continue;                                   /* <-- no amount check */
		if (scripteq(script, channel->shutdown_scriptpubkey[REMOTE]))
			continue;
		... OP_RETURN ... amount_sat_eq(...AMOUNT_SAT(0)) -> continue;
		return "output %zu goes to unknown script %s";
	}
	return NULL;                                                /* <-- tx considered valid */
}
```

The check verifies only that the tx spends our funding outpoint and that every output goes to one of the two known shutdown scripts (or a zero-value `OP_RETURN`). **Nowhere is there a check of how much of our output actually pays us.** There is no comparison of our output value against anything derived from `channel->our_msat`, no fee sanity bound, nothing.

Then, both close-tx paths forward to master and get committed as canonical channel state:

```c
// lightningd/simple_close_control.c:143 — our side of it
static void handle_simpleclosed_closee_broadcast(struct channel *channel, ...)
{
	...
	if (!fromwire_simpleclosed_closee_broadcast(tmpctx, msg, &tx, &sig)) ...
	const char *err = close_tx_check(tmpctx, channel, tx);      /* script-only check */
	...
	if (!check_tx_sig(tx, 0, NULL, funding_wscript, ...)) ...   /* peer's signature verified */

	channel_set_last_tx(channel, tx, &sig);                      /* line 179 */
	wallet_channel_save(ld->wallet, channel);                    /* line 180 — persisted to DB */
	...
}
```

```c
// lightningd/simple_close_control.c:95 — same shape for "our" closer tx (line 110 check,
// line 129 channel_set_last_tx(), line 130 wallet_channel_save())
```

`channel->last_tx` is then what master signs, broadcasts, sweeps and retries:

```c
// lightningd/peer_control.c:308
static struct bitcoin_tx *sign_and_send_last(...)
{
	tx = sign_last_tx(ctx, channel, last_tx, last_sig);          /* sign last_tx with our keys */
	wallet_transaction_add(ld->wallet, tx->wtx, 0, 0);
	wallet_extract_owned_outputs(ld->wallet, tx->wtx, false, NULL, NULL); /* book OUR amount from tx */
	broadcast_tx(...);                                           /* + retry loop ("keep trying!") */
}
```

(`drop_to_chain()` at `peer_control.c:356` and the delayed re-broadcast at `simple_close_control.c:188`/`:219-233` both broadcast `channel->last_tx`; `wallet_extract_owned_outputs()` books whatever amount the tx pays us into our wallet.)

Where does that tx come from? `closingd/simpleclosed.c`:

```c
// closingd/simpleclosed.c:301 — we are the "closee": input is the peer's
// `closing_complete` (fee_satoshis, locktime, scripts and signature TLVs are peer-chosen)
static struct bitcoin_tx *handle_closing_complete(...)
{
	fromwire_closing_complete(tmpctx, msg, &their_cid, &closer_script,
			&closee_script, &fee_sat, &locktime, &tlvs);   /* line 316 */
	...
	/* closer_amount = remote_sat - fee_sat ; closee_amount = local_sat ;
	 * variant (closer_only / closee_only / both) selected per protocol */
	chosen_tx = make_close_tx(...);                                /* lines ~418-444 */
	their_sig = check_their_sig(...chosen_tx, ...);                /* their sig over chosen_tx */
	...
	wire_sync_write(REQ_FD, take(towire_simpleclosed_closee_broadcast(NULL, chosen_tx, &their_sig)));
}
```

and

```c
// closingd/simpleclosed.c:453 — we are the "closer": input is the peer's `closing_sig` reply
static struct bitcoin_tx *handle_closing_sig(...)
{
	fromwire_closing_sig(...);                                      /* line 474 */
	/* fields compared against what we sent; one signature TLV accepted */
	/* signed_tx reconstructed from (possibly peer-influenced) fields    */
	if (!check_tx_sig(signed_tx, ...)) peer_failed_warn(...);      /* signature only */
	return signed_tx;                                               /* -> master (got_sig) */
}
```

### Why this is exploitable

1. **master trusts the close tx without checking that it pays us.** Whatever the subdaemon forwards (which is itself a function of the peer-supplied `closing_complete`/`closing_sig`) is accepted on scripts + funding-outpoint + signature only, saved via `channel_set_last_tx()` + `wallet_channel_save()`, signed, broadcast and booked into our wallet (`wallet_extract_owned_outputs()`). If the tx pays us less than our settled share, we never notice — the channel is recorded as closed against a tx that underpays us. That is a direct, silent loss of funds. (rustyrussell's fix commit says exactly this: *"lightningd: double-check closing tx actually pays correctly to us — simpleclosed checks it, but for thoroughness (and to prevent bugs and avoid any potential exploits in it) we need to check it too."*)

2. **the peer's close tx is made our canonical close tx.** `handle_simpleclosed_closee_broadcast()` stores the peer-proposed transaction (fee = attacker-chosen `fee_satoshis`, can be ~0) via `channel_set_last_tx()` and persists it to the database. Depending on which of the two internal messages reaches master last, `channel->last_tx` ends up being the *peer's* tx; master then signs, broadcasts, watches and keeps re-broadcasting that tx on retries/restarts, and sweeps our outputs from it. The close then runs entirely on attacker-chosen terms (fee, timing; on node restart the same low-fee tx is re-broadcast indefinitely). Upstream commit message: *"lightningd: don't save their closing tx. We want our own closing tx, but theirs might be too low-fee to use. Broadcast it, as a courtesy, but don't rely on it!"*

Both are peer-triggerable over the lightning wire (needs `option_simple_close` negotiated and a mutual close), which matches "peer to peer code, node is safe with `--offline`".

### Severity

Medium–high (would be high if `option_simple_close` were ever default):
remote peer, no prior state needed beyond one open channel, can end the mutual close on a tx of their choosing; worst case (combined with any subdaemon bug/regression or message corruption) master happily books an underpaying tx into the wallet → permanent loss of the difference. Also gets the peer a persistent, retryable canonical close tx to game.

### Affected code locations (file:line)

| # | location | problem |
|---|----------|---------|
| 1 | `lightningd/simple_close_control.c:37` (`close_tx_check`) | validates only input + scripts (+ zero-value OP_RETURN); no check that the output paying us is ≥ our expected share (`floor(our_msat)` minus fee), no fee bound |
| 2 | `lightningd/simple_close_control.c:143-180` (`handle_simpleclosed_closee_broadcast`) | peer-derived close tx: no payment check, then `channel_set_last_tx()` (`:179`) + `wallet_channel_save()` (`:180`) — peer tx becomes canonical and persisted |
| 3 | `lightningd/simple_close_control.c:95-130` (`handle_simpleclosed_got_sig`) | own close tx from subdaemon: no payment check before being made canonical (`:129`) and saved (`:130`) |
| 4 | `lightningd/simple_close_control.c:219-235` / `lightningd/peer_control.c:308-333,356+` | `drop_to_chain`/delayed broadcast sign, broadcast, sweep and endlessly retry `channel->last_tx` — whichever of our/their tx won the race |
| 5 | `closingd/simpleclosed.c:301+`, `:453+`, `common/close_tx.c:113+` | tx variants are functions of the peer message fields (`fee_satoshis`, variant choice, …); forwarded to master with only a signature re-check |

### Fix

Upstream has already been fixing exactly this on master (still an open PR at the time of the audited snapshot — nothing in-tree fixes it):

- https://github.com/ElementsProject/lightning/pull/9417 — *"Fix simple close checks"* by rustyrussell (reported by an internal LLM scan; label `26.06.x`, i.e. also for backport to the stable line). Key commits:
  - `62452ac5` — `lightningd: double-check closing tx actually pays correctly to us.` adds `expected_amt_tous = amount_msat_to_sat_round_down(channel->our_msat)` minus `feerate * SIMPLE_CLOSE_WEIGHT / 1000` to `close_tx_check()` and rejects the tx if no output pays us at least that (when above dust limit);
  - `2331cf21` — `lightningd: don't save their closing tx.` (`simpleclosed_closee_broadcast` → `simpleclosed_their_closing_tx`: validate with fee 0, then just `sign_and_broadcast_their_closing()` — sign + broadcast, do **not** `channel_set_last_tx()`);
  - supporting: `81e2ae7a` (shared `common/simple_close_weight.h`), `23970192` (wire rename `got_sig`/`closee_broadcast` → `our_closing_tx`/`their_closing_tx`), `ca1217c6` (persist `channel->simple_close_feerate`).
  - changelog line: "`experimental-simple-close` now doesn't save peer's closing transaction, so it can't be stuck with a too-low-fee tx."
- Affected: everything containing the feature (`ce119cd2f`, v26.06+), i.e. our snapshot; not yet in any release tag.
- Workaround: don't negotiate `--experimental-simple-close` with untrusted peers.

---

## Secondary (minor) note

`connectd`: a channel-scoped `WIRE_ERROR` can still be dropped when `channeld` exits at the same moment (`connectd/multiplex.c` `read_body_from_peer_done`, issue https://github.com/ElementsProject/lightning/issues/9424, unfixed at snapshot time). BOLT #1 requires failing the named channel on such errors; here the channel can just stay open after a peer-declared failure. Low severity, race window only; no direct fund-loss path found.

---

## How this was found

Repo snapshot = pure upstream `master` (`c1551c557`, tree diff-identical to GitHub), so the bug must be one of the recent-but-unfixed upstream ones in new peer-facing code. All new peer-facing code since v26.06 is the `experimental-simple_close` close path (`closingd/simpleclosed.c`, `lightningd/simple_close_control.c`, `common/close_tx.c`). Line-by-line trace of both close branches (`closer` and `closee`) of `simpleclosed.c` + master-side handlers + `drop_to_chain()`/`sign_and_send_last()` showed the two missing validations above; they match upstream PR #9417 (created 2026-08-14, still open at snapshot date) exactly.
