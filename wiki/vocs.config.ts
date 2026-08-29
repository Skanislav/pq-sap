import lean4 from '@shikijs/langs/lean4'
import { defineConfig } from 'vocs/config'
import leanLinks from './scripts/remark-lean-links.ts'
import { generatedSidebar } from './src/sidebar.gen'

const repo = 'https://github.com/Skanislav/pq-sap'

export default defineConfig({
  title: 'PQ Stealth Addresses',
  description:
    'Post-quantum stealth addresses as an ERC-5564 scheme extension: spec, decisions, research, Lean proofs and reference implementations.',
  renderStrategy: 'full-static',
  codeHighlight: { langs: [lean4] },
  markdown: { remarkPlugins: [leanLinks] },
  sidebar: [
    { text: 'Welcome', link: '/' },
    ...generatedSidebar.map((section) => ({ ...section, items: [...section.items] })),
    {
      text: 'Elsewhere',
      items: [
        { text: 'Presentation (Marp deck)', link: `${repo}/blob/main/docs/presentation/SUMMARY.md` },
        { text: 'Test vectors (v0)', link: `${repo}/tree/main/python/vectors/v0` },
        { text: 'ERC-5564', link: 'https://eips.ethereum.org/EIPS/eip-5564' },
        { text: 'ERC-6538', link: 'https://eips.ethereum.org/EIPS/eip-6538' },
        { text: 'pq.ethereum.org', link: 'https://pq.ethereum.org' },
      ],
    },
  ],
  topNav: [
    { text: 'Spec', link: '/spec/erc-draft' },
    { text: 'Decisions', link: '/spec/decisions' },
    { text: 'Proofs', link: '/lean' },
  ],
  socials: [{ icon: 'github', link: repo }],
})
