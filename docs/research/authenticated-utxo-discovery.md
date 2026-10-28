# PQ stealth addresses and authenticated UTXO discovery

Research integration note, 2026-09-14. This describes a proposed composition,
not an implemented native-UTXO integration or a normative ERC profile.

Our ML-KEM scheme targets recipient privacy: the viewing-key holder discovers
which one-time destinations belong to them. The
[authenticated UTXO discovery proposal](https://ethresear.ch/t/an-evaluation-of-authenticated-utxo-discovery-with-eip-8304-and-utxo-proof-tables/25828)
combines EIP-8304 recipient-range completeness with UTXO Proof Tables (UPT)
authenticating output fields. Current spent-state proofs answer the separate
question of whether those outputs remain unspent. These layers complement one
another; an output opening commitment is distinct from our recipient commitment.
EIP-8304 is a Draft Core EIP and UPT is a research proposal, so both remain
mutable dependencies rather than available protocol guarantees.

The proposed flow is:

1. Alice uses Bob's meta-address to derive a fresh destination `S` and publishes
   the KEM ciphertext and view tag through ERC-5564.
2. Alice creates a UTXO for `S`, subject to a compatible authorization route.
   Our current CREATE2 account binding does not establish native-UTXO spending
   compatibility by itself.
3. Bob obtains a complete, authenticated announcement stream and scans locally
   to discover `S`.
4. Bob queries UTXO creation events for `S`, verifies their complete recipient
   ranges and corresponding UPT opening proofs, then checks current spent state.

The key gap is announcement discovery. A complete UTXO query for `S` cannot
recover another destination whose announcement was withheld. A candidate design
uses [EIP-8304](https://eips.ethereum.org/EIPS/eip-8304) to prove a complete
announcer-address range and authenticate event classification. Its standard
index covers addresses and topics, so the ciphertext and metadata in log data
also need receipt proofs or another authenticated payload mechanism. The wallet
must cover the intended history range and anchor proofs to independently
authenticated canonical headers and roots. Commitments do not ensure that
providers retain or serve the underlying bytes.

For an ERC-5564 announcement, the wallet must join index entries at the same
`(block, transaction, log)` position: the announcer address; `topics[0]` as
the `Announcement` event signature; `topics[1]` as the expected scheme ID;
and `topics[2]` as `leftpad32(S)`. It must then verify the ciphertext and
metadata from that same receipt-log position. Separately valid index entries
from different logs are not evidence of one announcement.

This composition does not make the initial scan sublinear: the current scanner
decapsulates each candidate ciphertext before checking its view tag. Nor does
query authentication provide query privacy: submitting discovered destinations
to one RPC can let that provider group them. A privacy-preserving retrieval
strategy remains separate work. See the
[receive/scan reference](../TECHNICAL_SPEC.md) and
[security boundaries](../SECURITY_ANALYSIS.md).

A useful joint prototype would connect an authenticated ERC-5564 scan to the
UPT wallet, including exact event-to-output binding, canonical-history handling,
and a compatible spending adapter. Neither the proposal's experimental discovery
pipeline nor this composition establishes end-to-end PQ security; our concrete
commitment-profile privacy argument and spending assurance remain separate
obligations in the [ERC evidence map](../ERC_EVIDENCE.md).
