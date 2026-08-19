import { afterEach, describe, expect, it, vi } from 'vitest'

import { registry } from '@/contrib/registry'

import {
  COMPOSER_AREAS,
  type ComposerContextValue,
  type ComposerMiddleware,
  prepareComposerDraft,
  runComposerMiddleware
} from './contrib'

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
    const prepared = await runComposerMiddleware(draft)

    expect(prepared?.draft).toBe(draft)
    expect(prepared?.commit).toBeUndefined()
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

    const context = { runtimeSessionId: 'runtime-tile', storedSessionId: 'stored-tile-root' }

    await runComposerMiddleware({ text: 'tile turn' }, context)

    expect(contexts).toEqual([context, context])
    expect(contexts[0]).toBe(contexts[1])
    expect(contexts[0]).not.toBe(context)
    expect(Object.isFrozen(contexts[0])).toBe(true)
  })

  it('validates and detaches per-turn metadata produced by middleware', async () => {
    const metadata = { 'acme.review': { mode: 'strict' } }
    addMiddleware('metadata', d => ({ ...d, turnMetadata: metadata }))

    const result = await runComposerMiddleware({ text: 'review this' })

    expect(result?.draft.turnMetadata).toEqual(metadata)
    expect(result?.draft.turnMetadata).not.toBe(metadata)
    expect(result?.draft.turnMetadata?.['acme.review']).not.toBe(metadata['acme.review'])
  })

  it('treats invalid middleware metadata as a throwing contribution', async () => {
    addMiddleware('invalid', d => ({ ...d, text: 'must not land', turnMetadata: { acme: undefined } }) as never)
    addMiddleware('after', d => ({ ...d, text: `${d.text}!` }))

    expect((await runComposerMiddleware({ text: 'safe' }))?.draft).toEqual({ text: 'safe!' })
  })

  it('does not retain a callback from an invalid declared result', async () => {
    const commit = vi.fn()
    addMiddleware(
      'invalid-receipt',
      draft =>
        ({
          draft: { ...draft, text: 'must not land', turnMetadata: { acme: undefined } },
          onCommit: commit
        }) as never
    )

    const prepared = await runComposerMiddleware({ text: 'safe' })

    expect(prepared?.draft).toEqual({ text: 'safe' })
    expect(prepared?.commit).toBeUndefined()
    expect(commit).not.toHaveBeenCalled()
  })

  it('defers declared commit callbacks and invokes the chain exactly once', async () => {
    const commits: string[] = []
    addMiddleware('first', draft => ({
      draft: { ...draft, text: `${draft.text}a` },
      onCommit: () => {
        commits.push('first')
        throw new Error('one plugin cannot block the rest')
      }
    }))
    addMiddleware('second', draft => ({
      draft: { ...draft, text: `${draft.text}b` },
      onCommit: () => commits.push('second')
    }))

    const prepared = await runComposerMiddleware({ text: 'x' })

    expect(prepared?.draft.text).toBe('xab')
    expect(commits).toEqual([])

    prepared?.commit?.()
    prepared?.commit?.()

    expect(commits).toEqual(['first', 'second'])
  })

  it('discards declared callbacks when a later middleware cancels', async () => {
    const commit = vi.fn()
    addMiddleware('intent', draft => ({ draft, onCommit: commit }))
    addMiddleware('gate', () => null)

    expect(await runComposerMiddleware({ text: 'cancel me' })).toBeNull()
    expect(commit).not.toHaveBeenCalled()
  })

  it('does not re-run middleware for a prepared queued draft', async () => {
    let calls = 0
    addMiddleware('live-state', draft => {
      calls += 1

      return { ...draft, turnMetadata: { later: true } }
    })

    const turnMetadata = { queued: { mode: 'snapshot' } }
    const result = await prepareComposerDraft({ text: 'queued', turnMetadata }, true)

    expect(calls).toBe(0)
    expect(result?.draft.turnMetadata).toEqual(turnMetadata)
    expect(result?.draft.turnMetadata).not.toBe(turnMetadata)
    expect(result?.commit).toBeUndefined()
  })
})
