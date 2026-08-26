# Post-Quantum Stealth Addresses

A post-quantum stealth-address scheme for Ethereum, registered as a new
[ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) scheme ID and working
against the deployed ERC-5564 / ERC-6538 contracts with no protocol changes.

- **Detection** — ML-KEM-768 (FIPS 203). The announcement's ephemeral key is a
  KEM ciphertext; the shared secret drives a one-byte view tag and the address
  derivation. This is the part "harvest now, decrypt later" threatens, so it is
  the priority.
- **Spending** — an ML-DSA-65 (FIPS 204) key additively blinded by values
  derived from the shared secret. The sender computes the recipient's
  one-time address without learning any secret, exactly as in the secp256k1
  scheme, and the resulting signatures verify under stock FIPS 204 verifiers.

## Layout

| Path | What |
| --- | --- |
| [`docs/erc-draft.md`](docs/erc-draft.md) | ERC draft text (target scheme ID `2`) |
| [`docs/TECHNICAL_SPEC.md`](docs/TECHNICAL_SPEC.md) | Working technical specification |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Dated ADR log of design decisions |
| [`python/`](python/) | Executable Python spec, reference library, test vectors, benchmarks |
| [`js-client/`](js-client/) | TypeScript scanning client that reproduces the vectors byte for byte |
| [`lean/`](lean/) | Machine-checked Lean 4 / VCVio core (blinding identity, bounds, security games) |
| [`wiki/`](wiki/) | Mirrored documentation site source |

## Status

The technical spec, ADR log, v0 test vectors (with negative cases), the Python
reference library, the TypeScript client, and the Lean 4 core all exist and are
in the repository. What remains is the security write-up, community review,
and then the ERC text freeze — see [`docs/research/erc-submission-gap-analysis.md`](docs/research/erc-submission-gap-analysis.md).

The conformance vectors and checker are intended to enter the
[`ethereum/ERCs`](https://github.com/ethereum/ERCs) asset tree under CC0 when
the PR is opened.

## License

Copyright and related rights waived via [CC0-1.0](LICENSE).
