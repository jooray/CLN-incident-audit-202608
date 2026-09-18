# Verifying this repository

Everything in `timestamps/` was hashed and committed to the Bitcoin blockchain with
[OpenTimestamps](https://opentimestamps.org) at the moment it was finished, before
upstream published the `v26.06.7` source on 11 September 2026 at 11:42 UTC. The point of
the exercise was to predict fixes that were still secret, so the proofs are what make the
grading mean anything.

## Check one file

Each proof sits next to the file it attests, so:

```
pip install opentimestamps-client
ots verify timestamps/v1/CLN-AUDIT-OPUS-5.md
```

`ots verify` recomputes the file hash and walks the Merkle path to a Bitcoin block header.
It needs a local Bitcoin node to confirm the header. Without one, use

```
ots info timestamps/v1/CLN-AUDIT-OPUS-5.md.ots
```

which prints the committed SHA-256 and the block heights, and check the heights against any
block explorer. Each proof carries several attestations because it went to several
calendars; the earliest height is the one quoted below.

## Check everything

```
sha256sum -c SHA256SUMS
```

## What is committed where

| Bitcoin block | When (UTC) | SHA-256 | File |
|---|---|---|---|
| 964341 | 2026-08-27 19:56 | `f9371b85…ef2cd1a2` | `timestamps/v1/CLN-AI-AUDIT-BLOG.md` |
| 964341 | 2026-08-27 19:56 | `ba6db1d5…0c6eec4f` | `timestamps/v1/CLN-AUDIT-DEEPSEEK-V4-FLASH.md` |
| 964341 | 2026-08-27 19:56 | `bbcb326d…79bce503` | `timestamps/v1/CLN-AUDIT-GLM53-FLASH.md` |
| 964341 | 2026-08-27 19:56 | `a141ff31…ba8de7ae` | `timestamps/v1/CLN-AUDIT-OPUS-5.md` |
| 964341 | 2026-08-27 19:56 | `e1e32b6a…95efdd1eb` | `timestamps/v1/CLN-AUDIT.tar.gz` |
| 964525 | 2026-08-29 04:18 | `33fcd21d…ddcfc53f2` | `timestamps/binary-round/BINARY-AUDIT-opus5.md` |
| 964545 | 2026-08-29 08:24 | `4247ddae…cd4683ef` | `timestamps/v2/CLN-AI-AUDIT-BLOG.md` |
| 964545 | 2026-08-29 08:24 | `a2889b04…97e033f1b0` | `timestamps/v2/CLN-AUDIT-v2.tar.gz` |
| 964698 | 2026-08-30 06:42 | `4875793d…09dde791d` | `timestamps/binary-round/BINARY-AUDIT-deepseekv4-flash.md` |
| 964701 | 2026-08-30 06:59 | `7805aed1…04abaa47e` | `timestamps/binary-round/BINARY-AUDIT-glm-5.3-flash.md` |
| 964701 | 2026-08-30 06:59 | `6c9dc9dd…4ae370b77b` | `timestamps/binary-round/claims.txt` |
| 964808 | 2026-08-31 00:39 | `5d247000…686428fa63` | `timestamps/binary-round/BINARY-AUDIT-kimi-k3.md` |
| 964846 | 2026-08-31 07:46 | `a2763831…5c9b83a2` | `timestamps/v3/CLN-AI-AUDIT-BLOG.md` |
| 964846 | 2026-08-31 07:46 | `0cb1b09b…76b744de` | `timestamps/v3/CLN-AUDIT-v3.tar.gz` |
| 965063 | 2026-09-01 17:33 | `c70f3327…26a829ac` | `timestamps/v4/CLN-AI-AUDIT-BLOG.md` |
| 965063 | 2026-09-01 17:33 | `05cda0ae…0feb47d81b` | `timestamps/v4/CLN-AUDIT-v4.tar.gz` |

The timestamps stop at v4 deliberately. Upstream published the source ten days later, so a
proof made after that would attest to nothing but the date the grading was written. The
`README.md` here is the graded version, written after the answers were public, and it
carries no proof.

## The bundles

Each `CLN-AUDIT-v*.tar.gz` is the full set of reports as it stood at that version, and it is
the bundle rather than the loose files that was stamped for rounds 2 onward. The reading
copies in `source-audits/` and `binary-audits/` are byte-identical to the copies inside
`timestamps/v4/CLN-AUDIT-v4.tar.gz`:

```
mkdir /tmp/v4 && tar xzf timestamps/v4/CLN-AUDIT-v4.tar.gz -C /tmp/v4
diff -r source-audits /tmp/v4/CLN-AUDIT-v4 | grep -v '^Only in /tmp'
```

`CLN-AUDIT-GLM53-FULL.md` and `CLN-AUDIT-GROK-4-6.md` arrived after round 3 and have no
standalone proof; both are covered by the v4 bundle. The same is true of the Grok and Qwen
binary reports.

## What is not here

The Core Lightning source tree and the `v26.06.6` and `v26.06.7` release binaries. Get them
from upstream: the audit baseline is commit `c1551c557`, and the released source archive
published on 11 September hashes to
`b313d207e53f1e2dbf9fbac79d5af48c352e874a653390bddb81b52795a153dc`, a line that has been in
the maintainers' signed `SHA256SUMS-v26.06.7` since 28 August.
