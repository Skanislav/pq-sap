/**
 * The throwaway wallet must survive a page reload — i.e. its key round-trips
 * through localStorage. We test the pure persistence functions with a minimal
 * localStorage mock (the React hook just wraps these + a storage listener).
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { STORAGE_KEY, clearStoredKey, loadStoredKey, storeKey } from '../src/lib/throwaway.ts'

// Minimal localStorage shim on globalThis for the module under test.
function installStorage(): { store: Map<string, string> } {
  const store = new Map<string, string>()
  ;(globalThis as { localStorage?: unknown }).localStorage = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  }
  return { store }
}

const SAMPLE = `0x${'ab'.repeat(32)}` as const

test('key persists and reloads through localStorage', () => {
  const { store } = installStorage()
  assert.equal(loadStoredKey(), null, 'starts empty')

  storeKey(SAMPLE)
  assert.equal(store.get(STORAGE_KEY), SAMPLE, 'written under the versioned key')
  // A fresh read (as a reload would do) recovers the same key.
  assert.equal(loadStoredKey(), SAMPLE, 'reloads the key')

  clearStoredKey()
  assert.equal(loadStoredKey(), null, 'forgotten after clear')
})

test('malformed stored values are ignored', () => {
  installStorage()
  storeKey('not-a-key' as `0x${string}`)
  assert.equal(loadStoredKey(), null, 'rejects a non-key string')
})

test('storage being unavailable does not throw', () => {
  ;(globalThis as { localStorage?: unknown }).localStorage = {
    getItem: () => {
      throw new Error('disabled')
    },
    setItem: () => {
      throw new Error('disabled')
    },
    removeItem: () => {
      throw new Error('disabled')
    },
  }
  assert.doesNotThrow(() => storeKey(SAMPLE))
  assert.equal(loadStoredKey(), null, 'degrades to no persistence')
  assert.doesNotThrow(() => clearStoredKey())
})
