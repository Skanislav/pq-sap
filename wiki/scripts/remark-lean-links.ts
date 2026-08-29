import { visit } from 'unist-util-visit'
// Static import so the bundler inlines the index into dist/server/vocs.config.js.
// (A runtime fs read relative to import.meta.url breaks under `vocs preview`,
// where the bundled config lives in dist/server/ and the path no longer exists.)
import rawIndex from '../src/generated/theoremIndex.json' with { type: 'json' }

type IndexEntry = { route: string; slug: string; module: string }
type InlineCode = { type: 'inlineCode'; value: string }
type Link = { type: 'link'; url: string; children: InlineCode[] }
type Parent = { children: (InlineCode | Link | { type: string })[] }

const index = new Map<string, IndexEntry>(Object.entries(rawIndex as Record<string, IndexEntry>))

/**
 * Remark plugin that turns inline `code` spans containing a known Lean
 * declaration name into links to the per-module proof browser page.
 */
export default function remarkLeanLinks() {
  return (tree: Parent) => {
    visit(
      tree as never,
      'inlineCode',
      (node: InlineCode, childIndex: number | undefined, parent: Parent | undefined) => {
        if (!parent || typeof childIndex !== 'number') return
        const entry = index.get(node.value)
        if (!entry?.route || !entry.slug) return

        const link: Link = {
          type: 'link',
          url: `${entry.route}#${entry.slug}`,
          children: [{ type: 'inlineCode', value: node.value }],
        }
        parent.children.splice(childIndex, 1, link)
      },
    )
  }
}
