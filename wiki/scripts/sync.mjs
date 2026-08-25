#!/usr/bin/env node
// Mirrors the repository's markdown into wiki/src/pages so Vocs can serve it.
//
// The sources stay where they are (docs/, lean/docs/, README.md files, ...);
// this script copies them into route-shaped paths, rewrites relative links
// (other synced docs -> wiki routes, eip-*.md -> eips.ethereum.org, anything
// else in the repo -> GitHub) and emits src/sidebar.gen.ts for vocs.config.ts.
//
// Run: pnpm sync   (also runs automatically before `dev` and `build`)

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, posix, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const WIKI = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const ROOT = resolve(WIKI, '..')
const PAGES = join(WIKI, 'src', 'pages')
const GITHUB = 'https://github.com/Skanislav/pq-sap'
const BRANCH = 'main'

// Sidebar sections. Each item: [repo-relative source, route (no extension), sidebar label?].
// `glob` mirrors every *.md in a directory; labels default to the file's first H1
// (override with `titles`).
const SECTIONS = [
  {
    text: 'Overview',
    items: [
      ['plan.md', 'overview/plan', 'Project plan'],
    ],
  },
  {
    text: 'Specification',
    items: [
      ['docs/erc-draft.md', 'spec/erc-draft', 'ERC draft'],
      ['docs/TECHNICAL_SPEC.md', 'spec/technical-spec', 'Technical spec'],
      ['docs/DECISIONS.md', 'spec/decisions', 'Decisions & findings (ADR log)'],
      ['docs/classical-spend-hybrid.md', 'spec/classical-spend-hybrid', 'Classical-spend hybrid'],
    ],
  },
  {
    text: 'Research',
    glob: 'docs/research',
    route: 'research',
    titles: {
      'erc-submission-gap-analysis.md': 'ERC submission gap analysis',
      'hash-based-key-exchange.md': 'Hash-based key exchange vs ML-KEM',
      'hash-migration-blake2-binius.md': 'Hash policy after Poseidon',
      'poseidon2-stark-discovery.md': 'Poseidon2 + STARK discovery layer',
    },
  },
  {
    text: 'Proofs (Lean 4 / VCVio)',
    items: [
      ['lean/README.md', 'lean/index', 'Overview'],
    ],
    glob: 'lean/docs',
    route: 'lean',
    titles: {
      'announcement-model.md': 'The announcement model',
      'dksap-asymmetry.md': 'DKSAP asymmetry',
      'encodings.md': 'Encodings',
      'etheorem-lessons.md': 'Lessons from etheorem',
      'improvements.md': 'Proposed improvements',
      'lean-study-notes.md': 'Lean 4 study notes',
      'msis-reshaping.md': 'Spend forgery as MSIS',
      'spr-two-hop.md': 'KEM anonymity from SPR',
      'vcvio-pin.md': 'Tracking the VCVio pin',
      'vcvio-upstream.md': 'VCVio upstream findings',
    },
  },
  {
    text: 'Implementations',
    items: [
      ['python/README.md', 'impl/python', 'Python executable spec'],
      ['js-client/README.md', 'impl/js-client', 'TypeScript scanning client'],
      ['noir/README.md', 'impl/noir', 'Noir ownership circuit'],
      ['docs/pointer-signatures-poc.md', 'impl/pointer-signatures-poc', 'POC: (v, r, s) as pointers'],
    ],
  },
]

// ---------------------------------------------------------------------------

/** Expand globs into a flat list of {source, route, label, section}. */
function collect() {
  const out = []
  for (const section of SECTIONS) {
    const entries = []
    for (const [source, route, label] of section.items ?? []) entries.push({ source, route, label })
    if (section.glob) {
      const dir = join(ROOT, section.glob)
      for (const name of readdirSync(dir).filter((f) => f.endsWith('.md')).sort()) {
        const source = posix.join(section.glob, name)
        const route = posix.join(section.route, name.replace(/\.md$/, ''))
        entries.push({ source, route, label: section.titles?.[name] })
      }
    }
    for (const e of entries) {
      if (!existsSync(join(ROOT, e.source))) throw new Error(`sync: missing source ${e.source}`)
      out.push({ ...e, section: section.text })
    }
  }
  return out
}

function splitFrontmatter(text) {
  const m = text.match(/^---\r?\n[\s\S]*?\r?\n---\r?\n/)
  return m ? [m[0], text.slice(m[0].length)] : ['', text]
}

function firstH1(body) {
  const m = body.match(/^#\s+(.+?)\s*$/m)
  return m ? m[1].replace(/`/g, '') : undefined
}

/** Route for a page path: 'lean/index' -> '/lean', 'spec/decisions' -> '/spec/decisions'. */
const href = (route) => '/' + route.replace(/\/index$/, '')

function rewriteLinks(body, source, bySource) {
  const sourceDir = posix.dirname(source)
  return body.replace(/\]\(([^)\s]+)(\s+"[^"]*")?\)/g, (full, target, title = '') => {
    if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#') || target.startsWith('/')) return full
    const [pathPart, fragment = ''] = target.split(/(?=#)/)
    const repoPath = posix.normalize(posix.join(sourceDir, pathPart))

    if (bySource.has(repoPath)) return `](${href(bySource.get(repoPath).route)}${fragment}${title})`

    const eip = pathPart.match(/(?:^|\/)eip-(\d+)\.md$/)
    if (eip) return `](https://eips.ethereum.org/EIPS/eip-${eip[1]}${fragment}${title})`

    // ethereum/ERCs convention: the draft links the ERC repo's licence.
    if (/(?:^|\/)LICENSE\.md$/.test(pathPart)) {
      return `](https://github.com/ethereum/ERCs/blob/master/LICENSE.md${fragment}${title})`
    }

    const abs = join(ROOT, repoPath)
    if (!repoPath.startsWith('..') && existsSync(abs)) {
      const kind = statSync(abs).isDirectory() ? 'tree' : 'blob'
      return `](${GITHUB}/${kind}/${BRANCH}/${repoPath}${fragment}${title})`
    }
    console.warn(`sync: ${source}: unresolvable link ${target} (pointed at GitHub anyway)`)
    return `](${GITHUB}/blob/${BRANCH}/${repoPath}${fragment}${title})`
  })
}

/**
 * Vocs compiles `.md` through MDX, where a bare `<`, `{` or `}` in prose is a syntax
 * error and HTML comments are not allowed. Escape them outside fenced blocks and
 * inline code (the sources use no inline HTML, verified when this was written).
 */
function mdxSafe(body) {
  const stripped = body.replace(/<!--[\s\S]*?-->/g, '')
  const out = []
  let fence = null
  for (const line of stripped.split('\n')) {
    const open = line.match(/^\s*(`{3,}|~{3,})/)
    if (fence) {
      out.push(line)
      if (open && open[1][0] === fence[0] && open[1].length >= fence.length) fence = null
      continue
    }
    if (open) {
      fence = open[1]
      out.push(line)
      continue
    }
    // Split on inline code spans; escape only the prose segments.
    out.push(
      line
        .split(/(`+[^`]*?`+)/)
        .map((seg, i) => (i % 2 ? seg : seg.replace(/[<{}]/g, (c) => '\\' + c)))
        .join(''),
    )
  }
  return out.join('\n')
}

function banner(source) {
  return (
    `:::info[Mirrored page]\n` +
    `Source: [\`${source}\`](${GITHUB}/blob/${BRANCH}/${source}). Edit the source file; ` +
    `this copy is regenerated by \`pnpm sync\` in \`wiki/\`.\n` +
    `:::\n\n`
  )
}

function render(entry, bySource) {
  const raw = readFileSync(join(ROOT, entry.source), 'utf8')
  const [frontmatter, body] = splitFrontmatter(raw)
  const rewritten = mdxSafe(rewriteLinks(body, entry.source, bySource))

  // Put the banner right after the first H1 when the doc starts with one.
  const h1 = rewritten.match(/^\s*(#\s+.+?)\r?\n/)
  const page = h1
    ? rewritten.slice(0, h1[0].length) + '\n' + banner(entry.source) + rewritten.slice(h1[0].length).replace(/^\s*\n/, '')
    : banner(entry.source) + rewritten

  return frontmatter + page
}

function main() {
  const entries = collect()
  const bySource = new Map(entries.map((e) => [e.source, e]))

  // Wipe previously generated route directories so deleted sources disappear.
  const generatedDirs = new Set(entries.map((e) => e.route.split('/')[0]))
  for (const d of generatedDirs) rmSync(join(PAGES, d), { recursive: true, force: true })

  for (const e of entries) {
    const dest = join(PAGES, `${e.route}.md`)
    mkdirSync(dirname(dest), { recursive: true })
    writeFileSync(dest, render(e, bySource))
    e.label ??= firstH1(readFileSync(join(ROOT, e.source), 'utf8')) ?? e.route
  }

  const sidebar = SECTIONS.map((s) => ({
    text: s.text,
    items: entries.filter((e) => e.section === s.text).map((e) => ({ text: e.label, link: href(e.route) })),
  }))
  writeFileSync(
    join(WIKI, 'src', 'sidebar.gen.ts'),
    `// Generated by scripts/sync.mjs — do not edit.\n` +
      `export const generatedSidebar = ${JSON.stringify(sidebar, null, 2)} as const\n`,
  )

  console.log(`sync: wrote ${entries.length} pages into ${posix.relative(ROOT, PAGES)} + src/sidebar.gen.ts`)
}

main()
