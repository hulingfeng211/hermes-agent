import { describe, expect, it, vi } from 'vitest'

import { cloneTurnMetadata } from './turn-metadata'

describe('cloneTurnMetadata', () => {
  it('deep-clones a namespaced JSON map', () => {
    const source = {
      'acme.review': {
        enabled: true,
        labels: ['security', null, 3],
        options: { strict: false }
      }
    }

    const cloned = cloneTurnMetadata(source)!

    expect(cloned).toEqual(source)
    expect(cloned).not.toBe(source)
    expect(cloned['acme.review']).not.toBe(source['acme.review'])
    expect((cloned['acme.review'] as { labels: unknown[] }).labels).not.toBe(source['acme.review'].labels)
  })

  it.each([
    ['undefined', { acme: undefined }],
    ['a function', { acme: () => undefined }],
    ['a non-finite number', { acme: Number.NaN }],
    ['an invalid namespace', { 'acme feature': true }],
    ['a prototype object', { acme: new Date() }],
    ['a sparse array', { acme: Array(2) }]
  ])('rejects %s', (_label, value) => {
    expect(() => cloneTurnMetadata(value)).toThrow()
  })

  it('rejects accessor properties without invoking them', () => {
    const getter = vi.fn(() => 'secret')
    const value = { acme: {} } as Record<string, unknown>

    Object.defineProperty(value.acme as object, 'mode', { enumerable: true, get: getter })

    expect(() => cloneTurnMetadata(value)).toThrow(/data properties/)
    expect(getter).not.toHaveBeenCalled()
  })

  it('rejects cycles and oversized containers', () => {
    const cyclic: Record<string, unknown> = {}
    cyclic.self = cyclic

    expect(() => cloneTurnMetadata({ acme: cyclic })).toThrow(/cycles/)
    expect(() => cloneTurnMetadata({ acme: Array.from({ length: 256 }, (_, index) => index) })).toThrow(
      /256 JSON values/
    )
  })

  it('enforces the shared wire bounds and canonical namespace grammar', () => {
    const namespaces = Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`n${index}`, true]))
    let tooDeep: unknown = true

    for (let depth = 0; depth < 8; depth += 1) {
      tooDeep = { child: tooDeep }
    }

    expect(() => cloneTurnMetadata({ Acme: true })).toThrow(/namespace/)
    expect(() => cloneTurnMetadata({ 'acme/review': true })).toThrow(/namespace/)
    expect(() => cloneTurnMetadata(namespaces)).toThrow(/32 namespaces/)
    expect(() => cloneTurnMetadata({ acme: tooDeep })).toThrow(/maximum depth 8/)
    expect(() => cloneTurnMetadata({ acme: 'x'.repeat(16 * 1024) })).toThrow(/16384 UTF-8 bytes/)
  })
})
