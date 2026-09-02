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

Two kinds of pages:

- **Hand-written** — `.mdx` files committed under `src/pages/` (the landing
  page `index.mdx` and the AI guide `ai-guide.mdx`). Add more the same way.
- **Mirrored** — copies of markdown that lives elsewhere in the repo (`plan.md`,
  `docs/**`, `lean/README.md`, `lean/docs/*`, `python/README.md`, ...).
  `scripts/sync.mjs` regenerates them (it runs before `dev` and `build`, or
  via `pnpm sync`). They are git-ignored; **edit the source file, never the
  copy**. Every mirrored page carries a banner naming its source.

The sync script also:

- rewrites relative links between mirrored docs to wiki routes
  (`docs/TECHNICAL_SPEC.md` → `/spec/technical-spec`);
- turns EIP-style links (`./eip-7913.md`) into `eips.ethereum.org` URLs;
- points any other in-repo link (code, directories, vectors) at GitHub;
- writes `src/sidebar.gen.ts`, which `vocs.config.ts` spreads into the sidebar.

To add a mirrored doc, add it to `SECTIONS` in `scripts/sync.mjs` (files in a
`glob` directory — `docs/research/`, `lean/docs/` — are picked up
automatically; give them a short label in `titles`). If you add a new
top-level route directory, list it in `.gitignore`.

## Markdown for language models

Vocs emits the whole site as markdown alongside the HTML: `llms.txt` (index),
`llms-full.txt` (everything) and `assets/md/<route>.md` (one page). Nothing to
configure; the AI guide page (`src/pages/ai-guide.mdx`) documents the endpoints
for readers.
