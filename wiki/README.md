# Project wiki (Vocs)

Documentation site for the post-quantum ERC-5564 scheme, built with
[Vocs](https://vocs.dev).

```bash
cd wiki
nvm use            # Node 22 (see .nvmrc); Vocs 2 / Vite 8 need >= 20.19
pnpm install
pnpm dev           # sync + dev server at http://localhost:5173
pnpm build         # sync + static build into wiki/dist
pnpm preview
```

## How pages get here

The landing page is sourced from `docs/overview.md`; `pnpm sync` writes its
tracked `src/pages/index.mdx` copy. Edit the source, not that generated copy.
The AI guide remains a hand-written page at `src/pages/ai-guide.mdx`.

Other pages mirror markdown beside the code (`docs/**`, `lean/README.md`,
`lean/docs/*`, `python/README.md`, etc.) into gitignored route directories.
Every mirrored page names its source. The sidebar separates the key-exchange
ERC, reference implementations, KEM foundations, spending/account research,
Lean maintenance, and the complete generated proof browser. The browser covers
all tracks; being listed there does not make a proof an ERC requirement.

The sync script also:

- rewrites relative links between mirrored docs to wiki routes
  (`docs/TECHNICAL_SPEC.md` → `/spec/technical-spec`);
- turns EIP-style links (`./eip-7913.md`) into `eips.ethereum.org` URLs;
- points any other in-repo link (code, directories, vectors) at GitHub;
- writes `src/sidebar.gen.ts`, which `vocs.config.ts` spreads into the sidebar.

To add a mirrored doc, add it to `SECTIONS` in `scripts/sync.mjs` (files in a
`glob` directory — currently `docs/research/` and `lean/docs-proofs/` — are
picked up automatically unless excluded). Lean essays are explicitly grouped
by purpose; keep their existing routes when moving them between sections. If you add a new
top-level route directory, list it in `.gitignore`.

## Markdown for language models

Vocs emits the whole site as markdown alongside the HTML: `llms.txt` (index),
`llms-full.txt` (everything) and `assets/md/<route>.md` (one page). Nothing to
configure; the AI guide page (`src/pages/ai-guide.mdx`) documents the endpoints
for readers.
