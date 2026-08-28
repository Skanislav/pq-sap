import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { visit } from 'unist-util-visit'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const INDEX_PATH = path.resolve(__dirname, '../src/generated/theoremIndex.json')

const rawIndex = JSON.parse(fs.readFileSync(INDEX_PATH, 'utf-8'))
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
