# Core Lightning Peer-to-Peer Fund-Loss Audit

## Scope

Repository revision audited: `c1551c557` (`master`)

The review was limited to vulnerabilities triggerable by a live authenticated
Lightning peer. This matches the stated condition that a node running with
`--offline` is safe. The required impact bar was loss of funds, not channel
failure, daemon crash, payment failure, resource exhaustion, or a protocol
interoperability defect.

Reviewed components included:

- `channeld`: HTLC updates, commitment/revocation exchange, reestablishment,
  shutdown, splice negotiation, and splice transaction signatures.
- `openingd` and `dualopend`: legacy and dual-funded opening, RBF, funding
  signatures, reconnect, and channel-ready transitions.
- `closingd`: cooperative close and `wrong_funding` handling.
- `connectd` / `lightningd`: authenticated peer-to-channel routing, daemon
  handoff, durable state updates, and funding transaction broadcast.
- `onchaind`: peer force-close detection and resolution entry points.

## Result

No substantiated remotely triggerable loss-of-funds vulnerability was found in
the audited revision.

In particular, I found no peer-controlled message sequence that makes CLN:

- sign a transaction paying an attacker more than its negotiated entitlement;
- accept an attacker-selected commitment, splice, or cooperative-close output;
- reveal a local revocation secret before durable safe-state handling;
- persist an unsafe funding-signature state; or
- suppress an on-chain recovery action based only on an unverified peer claim.

The absence of a qualifying finding is important: several code paths initially
looked suspicious but have a terminating peer-failure path or a later
transaction/signature check that prevents fund loss.

## Security-Critical Checks Verified

### Normal channel updates and commitments

`channeld/channeld.c:2001-2336` reconstructs the candidate local commitment
from local channel state. It verifies the remote funding signature at
`2171-2192` and every HTLC signature at `2215-2232` before asking `hsmd` to
validate the commitment at `2250-2266`. The apparent early call to
`channel_rcvd_commit` at `2085-2102` only changes the short-lived channel
daemon state. A bad peer signature exits through `peer_failed_warn` before
commitment persistence or revocation.

`peer_failed_warn` is genuinely terminating, not merely a log helper:
`common/peer_failed.h:20-23` declares it `NORETURN` and
`common/peer_failed.c:53-65` reaches `peer_fatal_continue`, which exits at
`16-24`.

`revoke_and_ack` has strict expected-index validation
(`channeld/channeld.c:2586-2589`), signer validation for the expected secret
(`2591-2602`), and an exact derived-point comparison (`2611-2623`) before
advancing HTLC state (`2625-2639`). A peer cannot replay or substitute a
secret to make CLN discard a state or accept a false revocation.

Incoming fulfillments and failures require a known, committed, irrevocable
HTLC; fulfillments also verify the preimage. See
`channeld/full_channel.c:977-1088` and handlers at
`channeld/channeld.c:2656-2782`.

### Reconnection and data-loss protection

Reestablishment requires the exact channel ID
(`channeld/channeld.c:5865-5885`) and rejects invalid commitment/revocation
counter relationships (`6058-6131`). A claim that CLN is behind requires a
future local per-commitment secret validated through `hsmd`; only a genuine
proof suppresses unsafe unilateral publication. The relevant normal-channel
logic is `channeld/channeld.c:5479-5522`, with signer validation in
`hsmd/libhsmd.c:1113-1138`.

`connectd` routes messages by the extracted channel ID only within the
authenticated peer's channel set. The handoff also verifies the current
connection counter, preventing a stale connection from injecting a daemon
descriptor: `connectd/multiplex.c:1462-1523` and `1685-1720`.

### Splicing

Splice accounting is performed separately for initiator and accepter. It
starts from the current per-side channel balance, accounts for pending HTLCs,
attributes interactive inputs and outputs by serial-ID ownership, rejects a
withdrawal larger than that side's channel entitlement, and enforces each
side's input/output and fee contribution. See
`channeld/channeld.c:3404-3720`.

The old funding input is signed with `SIGHASH_ALL`; the peer's signature is
installed only on the locally constructed transaction at
`channeld/channeld.c:3995-4019`. This prevents a peer from changing inputs or
outputs after obtaining CLN's signature. Interactive transaction parsing also
rejects wrong owner parity, duplicate serial IDs/outpoints, and unauthorized
input/output removal in `common/interactivetx.c:526-784`.

### Dual-funded opening and funding signatures

Dual funding validates the completed PSBT, ownership attribution, funding
output, fee responsibilities, and commitment transaction before releasing the
local commitment signature. See `openingd/dualopend.c:736-985` and
`2169-2276`.

`WIRE_TX_SIGNATURES` is transaction-bound in
`openingd/dualopend.c:1300-1389`. A mismatching funding txid or a mismatching
witness count calls `open_err_warn` (`1348-1355`, `1377-1379`). Despite its
name, that routine calls the `NORETURN` `peer_failed_warn` routine
(`dualopend.c:384-396`), so execution does not continue to finalize a
witness or persist `remote_funding_sigs_rcvd`. This rules out the apparent
out-of-bounds witness access and false durable signature-state candidates.

The controller persists the remote-signature flag only after it receives the
valid `DUALOPEND_FUNDING_SIGS` notification, then broadcasts only a finalized
PSBT: `lightningd/dual_open_control.c:2125-2218`.

### Cooperative close

`closingd` deterministically constructs the close transaction from recorded
balances and the two shutdown scripts before accepting a peer signature:
`closingd/closingd.c:43-113` and `294-350`. The local close signature uses
`SIGHASH_ALL` (`hsmd/libhsmd.c:1434-1443`). A peer therefore cannot use a
shutdown or `closing_signed` message to redirect the local balance.

## Non-Qualifying Issues and Hardening Opportunities

These observations did not meet the loss-of-funds requirement and are not
reported as vulnerabilities.

1. Several normal `channeld` message handlers parse but do not independently
   compare their channel ID, for example `update_add_htlc`
   (`channeld/channeld.c:642-690`), `commitment_signed` (`2001-2044`), and
   `shutdown` (`2785-2866`). In the deployed architecture, `connectd`
   demultiplexes the message by channel ID before delivering it to the channel
   daemon. This is defense-in-depth debt rather than a current cross-channel
   fund-loss primitive.

2. `closing_signed` similarly parses a channel ID without comparison in
   `closingd/closingd.c:247-280`. The candidate signature still has to verify
   against the exact locally constructed close transaction, so it cannot
   select outputs or steal funds. Rejecting a mismatch would improve protocol
   hygiene.

3. `option_shutdown_wrong_funding` lets a remote opener nominate an alternate
   outpoint only for a negotiated, unused, non-dual-funded channel
   (`channeld/channeld.c:2822-2857`). This is a deliberately broad signing
   boundary and `closingd` does not independently validate the nominated UTXO
   (`closingd/closingd.c:110-111`). It is constrained to the channel's unique
   2-of-2 funding keys, and I found no way for a remote peer to turn it into a
   spend of unrelated local funds. Binding approved alternate outpoints in a
   validating external signer would nevertheless be prudent.

4. `update_view_from_inflights` has a suspicious index assignment at
   `channeld/channeld.c:3735-3736`: it tests
   `view[REMOTE].lowest_splice_amnt[REMOTE]` but writes index `LOCAL`.
   This can make reserve accounting overly conservative or inconsistent while
   there are inflight splices. The downstream commitment construction still
   rejects an unaffordable state, and no fund-loss chain was established. It
   merits a focused regression test and correction review.

## Residual Risk

A malicious peer can intentionally trigger warning/error handling, disconnect
a channel, abort a funding or splice negotiation, or cause a unilateral-close
workflow. These are availability and liquidity risks. They are materially
different from a peer stealing funds: the examined transaction and revocation
checks leave CLN with a locally persisted, signed safe commitment or the
normal on-chain resolution path.
