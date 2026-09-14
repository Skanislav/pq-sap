# Lean tooling and maintainer workflow

This material supports the proof library. It is not part of the key-exchange
wire specification and does not add ERC conformance requirements. For the
review path, use [ERC evidence](../../docs/ERC_EVIDENCE.md).

| Material | Purpose |
| --- | --- |
| [Lean overview](../README.md) | Current module classification and build checks |
| [VCVio pin](vcvio-pin.md) | Dependency upgrade procedure and historical validation records |
| [Upstream notes](vcvio-upstream.md) | Framework gaps and proposed contributions |
| [Study notes](lean-study-notes.md) | Lean/VCVio techniques and learning material |
| [Engineering lessons](etheorem-lessons.md) | Comparisons with other formalization projects |
| [Improvement log](improvements.md) | Historical proof/tooling backlog; not the current ERC critical path |
| `scripts/gen_browser.py` | Generates module pages and the theorem index from source |
| `scripts/check_citations.py` | Resolves supported source-range citations |
| `scripts/check_sizes.py` | Checks selected byte sizes; currently excludes commitment-vector replay |

The generated browser is a source reference across **all** tracks, including
spending. Listing a declaration there does not mean it is needed for the ERC
or that it establishes an end-to-end security claim. Edit source docstrings or
essays and regenerate; do not edit `lean/docs-proofs/` directly.

Full build and axiom-audit policy remains unchanged. An ERC-only Lean target
would require a later source-level dependency split; the present documentation
classification must not be used to bypass the existing checks.
