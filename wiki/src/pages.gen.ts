// deno-fmt-ignore-file
// biome-ignore format: generated types do not need formatting
// prettier-ignore
import type { PathsForPages } from 'waku/router'

// prettier-ignore
type Page =
  | { path: '/impl/js-client'; render: 'static' }
  | { path: '/impl/noir'; render: 'static' }
  | { path: '/impl/pointer-signatures-poc'; render: 'static' }
  | { path: '/impl/python'; render: 'static' }
  | { path: '/'; render: 'static' }
  | { path: '/lean/announcement-model'; render: 'static' }
  | { path: '/lean/dksap-asymmetry'; render: 'static' }
  | { path: '/lean/encodings'; render: 'static' }
  | { path: '/lean/etheorem-lessons'; render: 'static' }
  | { path: '/lean/improvements'; render: 'static' }
  | { path: '/lean'; render: 'static' }
  | { path: '/lean/lean-study-notes'; render: 'static' }
  | { path: '/lean/msis-reshaping'; render: 'static' }
  | { path: '/lean/proofs/anonymityfromspr'; render: 'static' }
  | { path: '/lean/proofs/blinding'; render: 'static' }
  | { path: '/lean/proofs/blindingrom'; render: 'static' }
  | { path: '/lean/proofs/constructiona'; render: 'static' }
  | { path: '/lean/proofs/controls'; render: 'static' }
  | { path: '/lean/proofs/demo'; render: 'static' }
  | { path: '/lean/proofs/dksap'; render: 'static' }
  | { path: '/lean/proofs/dksaporacle'; render: 'static' }
  | { path: '/lean/proofs/games'; render: 'static' }
  | { path: '/lean/proofs/invariants'; render: 'static' }
  | { path: '/lean/proofs/kemanonymity'; render: 'static' }
  | { path: '/lean/proofs/mlkem'; render: 'static' }
  | { path: '/lean/proofs/multirecipient'; render: 'static' }
  | { path: '/lean/proofs/multiunlink'; render: 'static' }
  | { path: '/lean/proofs/ownership'; render: 'static' }
  | { path: '/lean/proofs/reorder'; render: 'static' }
  | { path: '/lean/proofs/romuptobad'; render: 'static' }
  | { path: '/lean/proofs/sharedsecrethiding'; render: 'static' }
  | { path: '/lean/proofs/soundness'; render: 'static' }
  | { path: '/lean/proofs/sprtwohop'; render: 'static' }
  | { path: '/lean/spr-two-hop'; render: 'static' }
  | { path: '/lean/vcvio-pin'; render: 'static' }
  | { path: '/lean/vcvio-upstream'; render: 'static' }
  | { path: '/overview/plan'; render: 'static' }
  | { path: '/research/erc-submission-gap-analysis'; render: 'static' }
  | { path: '/research/hash-based-key-exchange'; render: 'static' }
  | { path: '/research/hash-migration-blake2-binius'; render: 'static' }
  | { path: '/research/poseidon2-stark-discovery'; render: 'static' }
  | { path: '/research/xwing-hybrid-kem'; render: 'static' }
  | { path: '/spec/classical-spend-hybrid'; render: 'static' }
  | { path: '/spec/decisions'; render: 'static' }
  | { path: '/spec/erc-draft'; render: 'static' }
  | { path: '/spec/technical-spec'; render: 'static' }

// prettier-ignore
declare module 'waku/router' {
  interface RouteConfig {
    paths: PathsForPages<Page>
  }
  interface CreatePagesConfig {
    pages: Page
  }
}
