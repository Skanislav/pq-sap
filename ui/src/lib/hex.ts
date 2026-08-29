/** Hex helpers shared by the UI and the scan worker. */

export const toHex = (b: Uint8Array): `0x${string}` =>
  ('0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')) as `0x${string}`

export function fromHex(s: string): Uint8Array {
  const h = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error('not a hex string')
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16)
  return out
}

export const shortHex = (s: string, head = 8, tail = 6): string =>
  s.length <= head + tail + 2 ? s : `${s.slice(0, head + 2)}…${s.slice(-tail)}`
