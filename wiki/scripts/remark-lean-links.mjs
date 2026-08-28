import { visit } from 'unist-util-visit'
// Static import so the bundler inlines the index into dist/server/vocs.config.js.
// (A runtime fs read relative to import.meta.url breaks under `vocs preview`,
// where the bundled config lives in dist/server/ and the path no longer exists.)
import rawIndex from '../src/generated/theoremIndex.json' with { type: 'json' }

const index = new Map(Object.entries(rawIndex))

/**
 * Remark plugin that turns inline `code` spans containing a known Lean
 * declaration name into links to the per-module proof browser page.
 */
export default function remarkLeanLinks() {
  return (tree) => {
    visit(tree, 'inlineCode', (node, childIndex, parent) => {
      if (!parent || typeof childIndex !== 'number') return
      const entry = index.get(node.value)
      if (!entry || !entry.route || !entry.slug) return

      parent.children.splice(childIndex, 1, {
        type: 'link',
        url: `${entry.route}#${entry.slug}`,
        children: [{ type: 'inlineCode', value: node.value }],
      })
    })
  }
}
