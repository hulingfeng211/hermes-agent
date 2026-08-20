import { afterEach, describe, expect, it, vi } from 'vitest'

import { registry } from '@/contrib/registry'

import { COMPOSER_AREAS, type ComposerContextValue, type ComposerMiddleware, runComposerMiddleware } from './contrib'

const disposers: Array<() => void> = []

function addMiddleware(id: string, handler: ComposerMiddleware['handler'], order?: number) {
  disposers.push(
    registry.register({ id, area: COMPOSER_AREAS.middleware, order, data: { handler } satisfies ComposerMiddleware })
  )
}

afterEach(() => {
  disposers.splice(0).forEach(d => d())
})

describe('runComposerMiddleware', () => {
  it('passes the draft through untouched when nothing is registered', async () => {
    const draft = { text: 'hello' }

    expect((await runComposerMiddleware(draft))?.draft).toBe(draft)
  })

  it('chains rewrites in registry order', async () => {
    addMiddleware('b', d => ({ ...d, text: `${d.text}b` }), 20)
    addMiddleware('a', d => ({ ...d, text: `${d.text}a` }), 10)

    expect((await runComposerMiddleware({ text: 'x' }))?.draft).toEqual({ text: 'xab' })
  })

  it('cancels the send when a handler returns null', async () => {
    addMiddleware('gate', () => null)
    addMiddleware('later', d => ({ ...d, text: 'never' }), 99)

    expect(await runComposerMiddleware({ text: 'x' })).toBeNull()
  })

  it('treats a throwing handler as pass-through', async () => {
    addMiddleware('boom', () => {
      throw new Error('broken plugin')
    })
    addMiddleware('after', d => ({ ...d, text: `${d.text}!` }), 99)

    expect((await runComposerMiddleware({ text: 'x' }))?.draft).toEqual({ text: 'x!' })
  })

  it('supports async handlers', async () => {
    addMiddleware('async', async d => ({ ...d, text: d.text.toUpperCase() }))

    expect((await runComposerMiddleware({ text: 'quiet' }))?.draft).toEqual({ text: 'QUIET' })
  })

  it('defers middleware side effects until a one-shot commit', async () => {
    const calls: string[] = []
    addMiddleware('first', draft => ({ draft, onCommit: () => calls.push('first') }))
    addMiddleware('second', draft => ({ draft, onCommit: () => calls.push('second') }))

    const prepared = await runComposerMiddleware({ text: 'send later' })

    expect(calls).toEqual([])
    prepared?.commit?.()
    prepared?.commit?.()
    expect(calls).toEqual(['first', 'second'])
  })

  it('isolates a throwing commit callback from later middleware callbacks', async () => {
    const after = vi.fn()
    addMiddleware('broken-commit', draft => ({
      draft,
      onCommit: () => {
        throw new Error('broken plugin cleanup')
      }
    }))
    addMiddleware('after', draft => ({ draft, onCommit: after }))

    const prepared = await runComposerMiddleware({ text: 'still send' })

    expect(() => prepared?.commit?.()).not.toThrow()
    expect(after).toHaveBeenCalledTimes(1)
  })

  it('passes one immutable target-session snapshot to the middleware chain', async () => {
    const contexts: ComposerContextValue[] = []
    addMiddleware('first', (draft, context) => {
      contexts.push(context)

      return draft
    })
    addMiddleware('second', (draft, context) => {
      contexts.push(context)

      return draft
    })

    const context = {
      connectionId: 'corp-net',
      profile: 'research',
      runtimeSessionId: 'runtime-tile',
      storedSessionId: 'stored-tile-root'
    }

    await runComposerMiddleware({ text: 'tile turn' }, context)

    expect(contexts).toEqual([context, context])
    expect(contexts[0]).toBe(contexts[1])
    expect(contexts[0]).not.toBe(context)
    expect(Object.isFrozen(contexts[0])).toBe(true)
  })
})
