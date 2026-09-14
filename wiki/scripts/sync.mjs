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
    text: 'Key-exchange ERC',
    items: [
      ['docs/overview.md', 'index', 'Overview'],
      ['docs/TECHNICAL_SPEC.md', 'spec/technical-spec', 'Technical reference'],
      ['docs/ERC_EVIDENCE.md', 'spec/erc-evidence', 'Evidence and proof scope'],
      ['docs/SECURITY_ANALYSIS.md', 'spec/security-analysis', 'Security boundaries'],
      ['docs/research/erc-submission-gap-analysis.md', 'research/erc-submission-gap-analysis', 'Submission roadmap'],
      ['plan.md', 'overview/plan', 'Current plan'],
      ['docs/DECISIONS.md', 'spec/decisions', 'Decision log'],
      ['docs/erc-draft.md', 'spec/erc-draft', 'ERC text (human-written)'],
    ],
  },
  {
    text: 'Reference implementations',
    items: [
      ['python/README.md', 'impl/python', 'Python reference'],
      ['js-client/README.md', 'impl/js-client', 'TypeScript client'],
    ],
  },
  {
    text: 'KEM proof foundations',
    items: [
      ['lean/README.md', 'lean/index', 'Proof scope and module map'],
      ['lean/docs/announcement-model.md', 'lean/announcement-model', 'Generic announcement model'],
      ['lean/docs/spr-two-hop.md', 'lean/spr-two-hop', 'KEM anonymity / SPR'],
      ['lean/docs/encodings.md', 'lean/encodings', 'Encoding results'],
    ],
  },
  {
    text: 'Spending and account research',
    items: [
      ['docs/SPENDING_RESEARCH.md', 'research/spending', 'Spending research guide'],
      ['docs/construction-a.md', 'research/construction-a', 'Construction A reference'],
      ['docs/construction-a-security.md', 'research/construction-a-security', 'Construction A security'],
      ['lean/docs/msis-reshaping.md', 'lean/msis-reshaping', 'Ownership / SIS research'],
      ['docs/research/eip-8288-summary.md', 'research/eip-8288-summary', 'EIP-8288 assessment'],
      ['docs/research/zk-sphincs-frames.md', 'research/zk-sphincs-frames', 'C13 ZK experiment'],
      [
        'docs/research/prefix-deploy-native-keys.md',
        'research/prefix-deploy-native-keys',
        'Deployment / native-key experiments',
      ],
      ['docs/classical-spend-hybrid.md', 'spec/classical-spend-hybrid', 'Classical-spend hybrid'],
      ['noir/README.md', 'impl/noir', 'MLWE ownership circuit'],
      ['docs/pointer-signatures-poc.md', 'impl/pointer-signatures-poc', 'Pointer-signature experiment'],
    ],
  },
  {
    text: 'Lean tooling and maintenance',
    items: [
      ['lean/docs/tooling.md', 'lean/tooling', 'Maintainer guide'],
      ['lean/docs/vcvio-pin.md', 'lean/vcvio-pin', 'VCVio pin'],
      ['lean/docs/vcvio-upstream.md', 'lean/vcvio-upstream', 'Upstream work'],
      ['lean/docs/lean-study-notes.md', 'lean/lean-study-notes', 'Study notes'],
      ['lean/docs/etheorem-lessons.md', 'lean/etheorem-lessons', 'Engineering lessons'],
      ['lean/docs/improvements.md', 'lean/improvements', 'Historical improvement log'],
    ],
  },
  {
    text: 'Other research and history',
    items: [['lean/docs/dksap-asymmetry.md', 'lean/dksap-asymmetry', 'Classical comparison']],
    glob: 'docs/research',
    route: 'research',
    exclude: [
      'erc-submission-gap-analysis.md',
      'eip-8288-summary.md',
      'zk-sphincs-frames.md',
      'prefix-deploy-native-keys.md',
    ],
    titles: { 'original-project-plan.md': 'Original cohort plan (historical)' },
  },
  {
    text: 'Generated proof browser (all tracks)',
    glob: 'lean/docs-proofs',
    route: 'lean/proofs',
    titles: {},
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
      // index.md first so a section's landing page heads its sidebar group.
      const names = readdirSync(dir)
        .filter((f) => f.endsWith('.md') && !section.exclude?.includes(f))
        .sort()
      for (const name of [...names.filter((n) => n === 'index.md'), ...names.filter((n) => n !== 'index.md')]) {
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
const href = (route) => (route === 'index' ? '/' : `/${route.replace(/\/index$/, '')}`)

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
        .map((seg, i) => (i % 2 ? seg : seg.replace(/[<{}]/g, (c) => `\\${c}`)))
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
    ? rewritten.slice(0, h1[0].length) +
      '\n' +
      banner(entry.source) +
      rewritten.slice(h1[0].length).replace(/^\s*\n/, '')
    : banner(entry.source) + rewritten

  return frontmatter + page
}

function main() {
  const entries = collect()
  const bySource = new Map(entries.map((e) => [e.source, e]))

  // Wipe previously generated route directories so deleted sources disappear.
  const generatedDirs = new Set(entries.filter((e) => e.route.includes('/')).map((e) => e.route.split('/')[0]))
  for (const d of generatedDirs) rmSync(join(PAGES, d), { recursive: true, force: true })

  for (const e of entries) {
    const dest = join(PAGES, `${e.route}.${e.route === 'index' ? 'mdx' : 'md'}`)
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
