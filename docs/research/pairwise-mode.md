# Pairwise mode: why fresh encapsulation per announcement stays

*2026-09-30. Analysis note for issue #39 (ethresear.ch scheme-4/5 "pairwise"
optimization: after one KEM exchange, later payments derive
`ss_i = H(r ‖ nonce_i)` and announce only the nonce). Extends the D-011
announcement-cost finding and the D-028 shape-check contract. No protocol
change; the ERC keeps fresh ML-KEM encapsulation per payment.*

## 1. Question

A first payment performs a full ML-KEM-768 encapsulation; the announcement
carries the 1,088 B ciphertext. The proposal asks: may *subsequent* payments
to the same recipient reuse the first shared secret — derive a channel secret
`r` from the first `ss`, then announce only a 32 B nonce with
`ss_i = H(r ‖ nonce_i)`, saving ~1,056 B of calldata per repeat payment?

## 2. What the proposal's own numbers say

- **L1:** a nonce announcement shrinks calldata from 1,316 B to roughly
  130 B (mostly zeros), so the EIP-7623 floor drops from 67.58 k to
  roughly 22–25 k gas — about **3× cheaper per repeat payment**
  (~$1.7 → ~$0.6 at D-011's anchors: 8 gwei, ETH $3,200).
- **L2:** D-011's own finding is that EIP-4844 blobs dissolve the
  announcement footprint (~$0.004 per announcement). The optimization targets
  the regime the deployment story de-emphasizes.

## 3. What reusing `r` breaks (each item verified against main, 7d5e15e)

**Deployed-announcer compatibility (D-014 / D-028).** The announcement must
remain a KEM ciphertext: `StealthKeyExchange.announce` shape-checks exactly
four ciphertext lengths (768 / 1,088 / 1,568 / 1,120 B, pairwise distinct);
a 32 B nonce reverts `UnsupportedCiphertextLength(32)`. Pairwise mode needs
a new scheme ID or an announcer bypass — a protocol fork, not a parameter.

**The Lean unlinkability reduction.** `StealthScheme.ofKEMFull`
(`lean/PqStealth/KEMAnonymity.lean:145`) types each announcement as a
*ciphertext* from `kem.encaps`; the decomposition
`unlinkAdvantage_ofKEMFull_le` rests on shared-secret hiding, aux
independence, and ciphertext anonymity — objects that cease to exist when
later announcements are bare PRF outputs. A pairwise scheme needs a new
scheme family whose repeat-announcement unlinkability term is PRF security of
`H(r ‖ ·)` under **public, attacker-influenced nonce inputs** (anyone may
post arbitrary nonces; the recipient derives garbage — harmless, but the
proof object is a chosen-input PRF game, not ML-KEM IND-CPA). None of the
existing `ofKEMFull` / `MultiRecipient` / `MultiUnlink` theorems transfer.

**Recipient scan cost and state.** The nonce does not say which channel it
belongs to. The recipient must try every stored `r`:
`ss_j = H(r_j ‖ nonce)` per correspondent, compare the view tag, then derive.
Scan cost per announcement becomes **O(S)** SHA-256s (S = correspondent count)
instead of one decapsulation — unbounded, never garbage-collected, and
dropping an `r` silently makes later payments invisible (no error, just no
detection). Alternatively a per-pair hint (e.g. `H(r)` prefix) restores O(1)
scan but is a stable **channel pseudonym**: an observer can count repeat
payments per pair and build frequency/timing graphs — an observable fresh
encapsulation does not have. There is no cheap option: O(S) scan or a channel
pseudonym.

**Forward secrecy.** Fresh mode: leaking one `ss` reveals one payment.
Pairwise: leaking `r` plus the *public* `spend_key` reproduces **every past
and future payment on the channel** without touching ML-KEM keys. Rotation
of `r` is exactly the silent-failure state problem above. The 0x02 opener's
sender-known-values argument survives unchanged (`r` plays the role of `ss`
in derivation), but the compromise scope regresses from per-payment to
per-channel.

## 4. Conclusion

Do not adopt for this ERC. Fresh encapsulation per announcement is what makes
the deployed-announcer compatibility (D-014/D-028), the `ofKEMFull`
reduction, the O(1)-storage scan, and the per-payment compromise bound hold
at once; the pairwise trade buys ~3.2× L1 announce gas (≈nothing on L2)
against regressions on all four. If the community wants pairwise repeat
payments, the right container is a **separate scheme ID with its own
security statement**; the list above is its pre-admission checklist.