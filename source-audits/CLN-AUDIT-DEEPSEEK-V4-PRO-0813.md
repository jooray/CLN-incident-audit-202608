# Core Lightning (CLN) audit report — peer-to-peer fund-loss vulnerability

- Repo audited: `/home/juraj/tmp/lightning`, upstream `master` @ `c1551c557`
- Auditor: opencode + `venice/deepseek-v4-pro-0813`
- Date: 2026-08-28
- Verdict: **1 significant loss-of-funds vulnerability in peer-to-peer code**, plus a small set of secondary defensive/robustness findings.

```
BUG:   lightningd/simple_close_control.c — the `option_simple_close` mutual
       close transaction is accepted, signed, stored as the canonical close
       tx ("last_tx"), broadcast, and its outputs booked into the wallet
       WITHOUT any check that it actually pays us our fair share.
TAKEN: close_tx_check() verifies input + output *scripts* (+ signature) only;
       it never compares the amount paid to us against channel->our_msat /
       the negotiated fee.
IMPACT: loss of funds — the channel is closed and booked against a peer-crafted
        close tx that can underpay us (fee is peer-chosen), silently and
        permanently.
FIX:    https://github.com/ElementsProject/lightning/pull/9417 (open at snapshot)
```

---

## Vulnerability: `option_simple_close` close tx accepted without a "pays us enough" check

### Component

The `experimental-simple-close` feature (`OPT_SIMPLE_CLOSE`, feature bits 60/61).
Introduced after v26.06, all new peer-facing code:

- `lightningd/simple_close_control.c` — `close_tx_check()` (master-side validation)
- `closingd/simpleclosed.c` — `handle_closing_complete()`, `handle_closing_sig()`
- `common/close_tx.c` — `create_simple_close_tx()`
- `lightningd/peer_control.c` — `sign_and_send_last()` / `drop_to_chain()`, which
  consume `channel->last_tx`.

**Triggered by a remote peer** over the wire (mutual close with
`option_simple_close` negotiated). Nothing happens with `--offline` — consistent
with the hint.

### Root cause

`close_tx_check()` (`lightningd/simple_close_control.c:37`) is the *only*
validation applied to the close transaction before it is committed as canonical
channel state. It checks:

```c
// lightningd/simple_close_control.c:37
static const char *close_tx_check(const tal_t *ctx,
				  const struct channel *channel,
				  const struct bitcoin_tx *tx)
{
	if (tx->wtx->num_inputs != 1)
		return ...;
	if (!wally_tx_input_spends(&tx->wtx->inputs[0], &channel->funding))
		return ...;
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		...
		if (scripteq(script, channel->shutdown_scriptpubkey[LOCAL]))
			continue;                                    /* <- no amount check */
		if (scripteq(script, channel->shutdown_scriptpubkey[REMOTE]))
			continue;
		... OP_RETURN + zero-value ... continue;
		return "output %zu goes to unknown script %s";
	}
	return NULL;                                            /* <- tx considered valid */
}
```

It validates:
1. exactly one input;
2. that input spends the funding outpoint;
3. every output script is one of the two known shutdown scripts (or a zero-value
   OP_RETURN).

It does **not** validate anything about **how much** our output pays us. There is
no comparison of the tx output value against `channel->our_msat`, no fee sanity
bound, nothing. The amount our output carries is taken on faith from the
subdaemon, which in turn derives it from peer-message fields.

### How the peer controls the tx (and the fee)

The close tx is a function of the peer's `closing_complete` / `closing_sig`
messages. In `closingd/simpleclosed.c`, the fee and the output split are computed
from peer-supplied fields:

```c
// closingd/simpleclosed.c:329  (we are the closee; the peer is the closer)
fromwire_closing_complete(tmpctx, msg, &their_cid, &closer_script,
		&closee_script, &fee_sat, &locktime, &tlvs);   /* fee_sat is peer-chosen */
...
// closingd/simpleclosed.c:371-389
if (!amount_sat_sub(&remote_sat, funding_sats, local_sat))
	remote_sat = AMOUNT_SAT(0);
if (is_valid_op_return(closer_script, ...))
	closer_amount = AMOUNT_SAT(0);
else if (!amount_sat_sub(&closer_amount, remote_sat, fee_sat))
	peer_failed_warn(...);                                  /* only bounds fee vs peer balance */
if (is_valid_op_return(closee_script, ...))
	closee_amount = AMOUNT_SAT(0);
else
	closee_amount = local_sat;                              /* our output = our full msat */
```

The peer controls `fee_satoshis` (and the variant/`OP_RETURN` selection). The
subdaemon computes `closer_amount = remote_sat - fee_sat` and
`closee_amount = local_sat`, then forwards the resulting tx to master. Master's
`close_tx_check()` accepts it on scripts + funding-outpoint + signature **and never
re-derives or checks the amounts**.

Both paths then make the tx canonical and persist it:

```c
// lightningd/simple_close_control.c:95  (closer path: we built it)
handle_simpleclosed_got_sig(...)
{
	...
	close_tx_check(...);              /* script-only check */
	check_tx_sig(...);                /* peer sig verified */
	channel_set_last_tx(channel, tx, &sig);   // line 129
	wallet_channel_save(ld->wallet, channel); // line 130
}

// lightningd/simple_close_control.c:143 (closee path: **the peer built it**)
handle_simpleclosed_closee_broadcast(...)
{
	...
	close_tx_check(...);              /* script-only check */
	check_tx_sig(...);                /* peer sig verified */
	channel_set_last_tx(channel, tx, &sig);   // line 179
	wallet_channel_save(ld->wallet, channel); // line 180
}
```

`channel->last_tx` is then signed, broadcast, swept and retried by master, and its
outputs are booked into the wallet:

```c
// lightningd/peer_control.c:308  sign_and_send_last()
{
	tx = sign_last_tx(ctx, channel, last_tx, last_sig);
	wallet_transaction_add(ld->wallet, tx->wtx, 0, 0);
	wallet_extract_owned_outputs(ld->wallet, tx->wtx, false, NULL, NULL); // books our amount from tx
	broadcast_tx(...);   /* + endless re-broadcast on retry/restart */
}
```

### Why this is a loss of funds

1. **master trusts a peer-derived close tx without checking it pays us.**
   Whatever the subdaemon forwards is accepted on scripts + funding-outpoint +
   signature only, stored via `channel_set_last_tx()` + `wallet_channel_save()`,
   signed, broadcast, watched and booked (`wallet_extract_owned_outputs()` books
   whatever amount the tx actually pays us). If the tx pays us less than our
   settled share, we never notice — the channel is closed and booked against an
   underpaying tx. That is a direct, silent, permanent loss of funds.

2. **The peer's close tx is made our canonical close tx.** In the closee path
   (`handle_simpleclosed_closee_broadcast`) the peer-proposed transaction is stored
   via `channel_set_last_tx()` and persisted. On retries/restarts master keeps
   signing, broadcasting and sweeping that same peer-chosen tx. The close then runs
   entirely on attacker-chosen fee/terms, and the fee is attacker-controlled (can
   be ~0).

The fee is chosen by the peer (closer). In the normal subdaemon flow our own
output is set to `local_sat`, so a *correct* subdaemon does not underpay us — but
master has no independent check, so any subdaemon bug/regression, wire corruption,
or subtle peer manipulation translates directly into a booked loss. This is
exactly what the upstream fix addresses ("for thoroughness ... and to prevent bugs
and avoid any potential exploits in it").

### Severity

**High** for any node that negotiates `option_simple_close` with an untrusted peer
(it is opt-in/experimental and off by default). A remote peer with one open
channel can steer the mutual close onto a transaction of their choosing; master
books the (potentially reduced) amount into our wallet with no validation.

### Affected locations

| # | location | problem |
|---|----------|---------|
| 1 | `lightningd/simple_close_control.c:37` (`close_tx_check`) | validates input + scripts (+ zero-value OP_RETURN) only; no check that our output ≥ our settled share, no fee bound |
| 2 | `lightningd/simple_close_control.c:143-180` (`handle_simpleclosed_closee_broadcast`) | peer-derived close tx: no amount check, then `channel_set_last_tx()` (`:179`) + `wallet_channel_save()` (`:180`) |
| 3 | `lightningd/simple_close_control.c:95-130` (`handle_simpleclosed_got_sig`) | our own close tx: no amount check before being made canonical (`:129`) and saved (`:130`) |
| 4 | `closingd/simpleclosed.c:302+` (`handle_closing_complete`), `:472+` (`handle_closing_sig`) | tx variants are a function of the peer's `fee_satoshis` / variant selection; forwarded to master with only a signature re-check |
| 5 | `lightningd/peer_control.c:308-333` (`sign_and_send_last`) / `:356+` (`drop_to_chain`) | sign, broadcast, sweep, endlessly retry, and book `channel->last_tx` (whichever tx won the race) via `wallet_extract_owned_outputs()` |

### Fix

Upstream already fixed this on master (open PR at snapshot time; nothing in-tree
fixes it):

- https://github.com/ElementsProject/lightning/pull/9417 — *"Fix simple close checks"* (rustyrussell).
  - Adds `expected_amt_tous = amount_msat_to_sat_round_down(channel->our_msat)`
    (minus `feerate * SIMPLE_CLOSE_WEIGHT / 1000`) to `close_tx_check()` and
    rejects any tx whose output paying us is below that.
  - *"don't save their closing tx"*: the closee-broadcast path is changed so the
    peer's tx is only signed/broadcast as a courtesy, not saved via
    `channel_set_last_tx()`.
- Workaround: do not negotiate `--experimental-simple-close` with untrusted peers.

---

## Secondary findings (robustness / accounting, lower confidence, not directly peer-lootable)

These are in the splice path (`channeld`), which is also peer-to-peer fund-moving
code. They are real bugs/instance of unsafe arithmetic but do not appear to give a
remote peer a direct, proven theft path in the default (in-process HSM) config.

| # | location | issue |
|---|----------|-------|
| A | `channeld/channeld.c:3728` `update_view_from_inflights()` | `s64 splice_amnt = inflights[i]->amnt.satoshis;` uses the **absolute** funding amount instead of the relative `inflights[i]->splice_amnt`. `lowest_splice_amnt` is documented as "0 or negative" (a *relative* splice change), but is fed a positive absolute value, so the local pending splice-out is never accounted for in `get_room_above_reserve()` (`full_channel.c:430`). Breaks the channel-reserve check for a pending local splice-out. Also index mismatches in the same function (e.g. `:3735-3736` compares `[REMOTE]`, assigns `[LOCAL]`). |
| B | `channeld/channeld.c:3323/3344` `relative_splice_balance_fundee()` | `u64 push_value` is assigned from the signed `accepter_relative`/`opener_relative`; a peer splice-out (negative) sign-extends to a huge value sent to the HSM signer's `setup_channel` `push_val`. Stub in `hsmd/libhsmd.c:372` ignores it, so only affects fully-validating external signers (VLS). |
| C | `common/amount.c:673` `amount_msat_sub_fee()` | `1000000 + fee_proportional_millionths` (`int` + `u32`) overflows for `fee_proportional_millionths > 4293967295` — the same pattern as the recently-fixed `onion_decode.c` blinded-forward bug. Currently only reached from the askrene payment plugin (route computation), not the core forwarding path. |
| D | `channeld/channeld.c:1290` `sats_diff()` / `common/amount.c:405` `amount_msat_add_sat_s64()` | unchecked `s64` cast/subtract ("can wrap") and `-b` negation of `s64` (UB at `INT64_MIN`). Each is individually guarded further downstream (checked add/abort), so no confirmed theft. |

If the goal is backport-hardened peer-to-peer fund handling, A and B deserve the
same style of fix as the primary finding (explicit bounds + relative-vs-absolute
type clarity), but the **clear, exploitable loss-of-funds bug is the
`option_simple_close` close-tx amount check** above.

---

## Method

Repo is a clean upstream `master` snapshot. The recent security-fix series
(marginal_feerate overflow, funding_satoshis bound, blinded-forward fee overflow,
zero next_commitment_number) all revolve around *peer-controlled values*, which
pointed the audit at the newest peer-facing fund-movement code since v26.06:
`option_simple_close`. A line-by-line trace of `closingd/simpleclosed.c` (both
closer and closee branches) → `lightningd/simple_close_control.c` →
`channel_set_last_tx` → `sign_and_send_last`/`drop_to_chain` →
`wallet_extract_owned_outputs` shows the close tx is accepted and booked without an
amount check, matching upstream PR #9417 exactly. Secondary findings come from a
parallel review of the splice arithmetic in `channeld`.