/**
 * Demo-grade key persistence: recipient seeds in localStorage.
 * This is a reference UI — a real wallet would keep these in secure storage.
 */

import { fromHex, toHex } from './hex.ts'
import type { RecipientSeeds } from './keygen.ts'

const KEY = 'pq-stealth.recipient-seeds.v1'

export function loadSeeds(): RecipientSeeds | null {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return null
    const j = JSON.parse(raw) as { zeta: string; kemD: string; kemZ: string }
    return { zeta: fromHex(j.zeta), kemD: fromHex(j.kemD), kemZ: fromHex(j.kemZ) }
  } catch {
    return null
  }
}

export function saveSeeds(s: RecipientSeeds): void {
  try {
    localStorage.setItem(KEY, JSON.stringify({ zeta: toHex(s.zeta), kemD: toHex(s.kemD), kemZ: toHex(s.kemZ) }))
  } catch {
    /* private windows etc. — keys stay in-memory only */
  }
}

export function clearSeeds(): void {
  try {
    localStorage.removeItem(KEY)
  } catch {
    /* ignore */
  }
}

// --- classical-spend hybrid seeds ------------------------------------------

import type { ClassicalSeeds } from './classical.ts'

const CLASSICAL_KEY = 'pq-stealth.classical-seeds.v1'

export function loadClassicalSeeds(): ClassicalSeeds | null {
  try {
    const raw = localStorage.getItem(CLASSICAL_KEY)
    if (!raw) return null
    const j = JSON.parse(raw) as { spendSeed: string; kemD: string; kemZ: string }
    return {
      spendSeed: fromHex(j.spendSeed),
      kemD: fromHex(j.kemD),
      kemZ: fromHex(j.kemZ),
    }
  } catch {
    return null
  }
}

export function saveClassicalSeeds(s: ClassicalSeeds): void {
  try {
    localStorage.setItem(
      CLASSICAL_KEY,
      JSON.stringify({
        spendSeed: toHex(s.spendSeed),
        kemD: toHex(s.kemD),
        kemZ: toHex(s.kemZ),
      }),
    )
  } catch {
    /* private windows etc. */
  }
}

export function clearClassicalSeeds(): void {
  try {
    localStorage.removeItem(CLASSICAL_KEY)
  } catch {
    /* ignore */
  }
}
