# Core Lightning P2P Fund-Loss Audit

## Scope

This review covered the peer-to-peer channel paths in the repository, with emphasis on remotely supplied messages and state transitions that could cause CLN to sign, broadcast, or accept a transaction which transfers more channel value to the peer than the valid channel state permits. The offline case is out of scope as requested.

## Result

I found **no confirmed remotely exploitable loss-of-funds vulnerability** in the reviewed code.

The principal suspicious defect is a C operator-precedence error in splice pending-HTLC bookkeeping. After tracing the values into the actual balance checks and transaction construction, it does not currently provide a fund-loss primitive: the two affected buckets are summed together for total funding, while the per-side splice-out checks use the channel's actual `owed[LOCAL]` and `owed[REMOTE]` balances.

## Candidate 1: Reversed pending-HTLC role bookkeeping

**Location:** `channeld/channeld.c:3419-3442`, especially line 3434.

```c
if (htlc_owner(htlc) == opener ? LOCAL : REMOTE)

```

This parses as:

```c
if ((htlc_owner(htlc) == opener) ? LOCAL : REMOTE)
```

Since `LOCAL` is zero and `REMOTE` is one (`common/htlc.h:9-12`), the selected role appears inverted. The intended expression was likely something equivalent to:

```c
if (htlc_owner(htlc) == (opener ? LOCAL : REMOTE))
```

### Why it looked exploitable

An authenticated channel peer can arrange for a splice while HTLCs are pending. Incorrect role attribution could, in principle, allow a peer to claim that the counterparty's pending HTLC value supports its own splice withdrawal.

### Why this is not a confirmed fund-loss issue

`check_balances()` initializes the per-role `in[]` values directly from the current channel balances at `channeld/channeld.c:3422-3425`. The per-side withdrawal checks at `3452-3466` use those values, not `pending_htlcs[]`.

The affected buckets are only accumulated into the combined `funding_amount` at `3487-3500`. That combined amount is used to determine the new channel output amount. Both buckets are included, so swapping their labels does not change the total. The actual per-side output checks at `3546-3592` likewise compare role-specific `in[]` and `out[]` values, and the channel output is located by the expected 2-of-2 script and assigned the validated total at `channeld/channeld.c:3217-3244` and `4341-4350`.

### Impact and severity

This is a real correctness/maintainability bug and should be fixed because future changes could make the role-specific arrays security-sensitive. In the current call path I could not construct a peer message sequence that turns it into peer-controlled excess funding or a theft transaction.

**Status:** Not a qualifying fund-loss vulnerability.

## Candidate 2: Missing explicit channel-ID checks in some HTLC handlers

**Locations:**

- `channeld/channeld.c:642-691`
- `channeld/channeld.c:2656-2688`
- `channeld/channeld.c:2691-2728`
- `channeld/channeld.c:2730-2782`

The handlers decode a peer-supplied `channel_id` and then process the update against the one channel attached to the daemon, without an immediate local comparison. The same pattern exists for some update messages.

This is a protocol/state-integrity issue, but CLN supports one channel per peer in this daemon and the resulting HTLC operation remains subject to ID, commitment, state, amount, preimage, and signature validation. I found no cross-channel value mix-up or route to an unauthorized output.

**Status:** Not a qualifying fund-loss vulnerability. Add explicit checks for defense in depth.

## Candidate 3: Premature remote shutdown

**Locations:** `channeld/channeld.c:2785-2880`, especially `2800-2801` and `2860-2878`.

The code explicitly notes that shutdown should not be accepted while the channel is active in some leased-funds cases. A peer can therefore request cooperative shutdown earlier than expected.

The shutdown message does not choose arbitrary balances or outputs. The close transaction is constructed locally, and closing signatures are validated against the locally constructed transaction variants in `closingd/closingd.c:285-350`. The behavior can cause premature closure or availability loss, but I found no fund theft or invalid allocation path.

**Status:** Not a qualifying fund-loss vulnerability.

## Candidate 4: Splice fallback locktime is not locally validated

**Location:** `channeld/channeld.c:4338-4339`.

```c
/* DTODO validate locktime */
ictx->current_psbt->fallback_locktime = locktime;
```

The remote peer can influence the negotiated fallback locktime. This can cause splice failure, delay, or policy/consensus problems, but the existing funding output remains protected by the prior channel state until the splice is locked. I found no path to an unauthorized spend.

**Status:** Not a qualifying fund-loss vulnerability.

## Security controls verified

- Received commitment signatures are checked against locally reconstructed transactions: `channeld/channeld.c:2140-2172`.
- HTLC signatures are checked individually against reconstructed HTLC transactions: `channeld/channeld.c:2194-2231`.
- Revocation secrets are checked by the HSM and against the expected prior commitment point: `channeld/channeld.c:2591-2623`.
- Fulfill preimages are SHA256-checked against the stored payment hash: `channeld/full_channel.c:977-1004`.
- HTLC removal requires the appropriate committed and irrevocable state: `channeld/full_channel.c:1006-1087`.
- Splice balance checks attribute non-channel inputs and outputs by validated serial-ID parity and require role-specific input coverage: `channeld/channeld.c:2964-3003`, `3469-3474`, `3481-3485`, and `3546-3592`.
- The splice funding output is found by the expected 2-of-2 witness script, not by an attacker-selected index: `channeld/channeld.c:3217-3244`.
- Interactive transaction input/output serial ownership and duplicate IDs are checked in `common/interactivetx.c:520-539`, `647-674`, `702-720`, and `751-784`.
- Closing signatures are validated against locally constructed close transactions: `closingd/closingd.c:285-350`.
- Gossip signatures cover the complete signed payload: `gossipd/sigcheck.c:29-42`, `72-113`, and `137-161`.
- Wire/TLV decoding enforces bounds and canonical encodings: `wire/fromwire.c:15-42` and `wire/tlvstream.c:155-299`.

## Recommendations

1. Fix line 3434 to compare `htlc_owner(htlc)` with the selected side using parentheses, and add ownership-sensitive splice tests for both opener/accepter roles with pending HTLCs.
2. Add a common channel-ID validation helper and call it immediately after decoding every channel-scoped peer message.
3. Enforce the shutdown state rules for active channels and validate splice locktimes against the protocol and local chain requirements.
4. Add an end-to-end test asserting that a peer cannot splice out pending HTLC value belonging to the other side.

## Conclusion

The audit did not establish a remotely reachable peer-to-peer vulnerability that causes loss of funds. The splice precedence defect is worth fixing, but the currently implemented downstream accounting prevents it from changing the side-specific withdrawal authorization or the total channel output in a way that yields a theft transaction.
