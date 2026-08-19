import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { registry } from '@/contrib/registry'
import {
  $parkedQueueSessions,
  $queuedPromptsBySession,
  enqueueQueuedPrompt,
  getQueuedPrompts,
  isQueueParked,
  parkQueuedPrompts
} from '@/store/composer-queue'

import type { QueueEditState } from '../composer-utils'
import { COMPOSER_AREAS, type ComposerMiddleware } from '../contrib'
import type { ChatBarProps } from '../types'

import { useComposerQueue } from './use-composer-queue'

// The park ↔ drain contract at the hook level. The store tests pin the pure
// pieces (shouldAutoDrain, park bookkeeping); these pin the wiring — the
// auto-drain effect honoring the park, and send-now-while-busy lifting it so
// the settle drain still flows (the regression that sank the old blanket
// interrupt latch).

const SESSION_KEY = 'stored-session-queue-hook'

const contributionDisposers: Array<() => void> = []

function renderQueueHook(
  overrides: {
    activeQueueSessionKeyRef?: { current: string | null }
    busy?: boolean
    onCancel?: () => void
    text?: string
  } = {}
) {
  const onSubmit = vi.fn<ChatBarProps['onSubmit']>(async () => true)
  const onCancel = overrides.onCancel ?? vi.fn()
  const queueEditRef: { current: QueueEditState | null } = { current: null }
  const draftRef = { current: overrides.text ?? '' }
  const clearDraft = vi.fn()

  const hook = renderHook(
    ({ busy }: { busy: boolean }) =>
      useComposerQueue({
        activeQueueSessionKey: SESSION_KEY,
        activeQueueSessionKeyRef: overrides.activeQueueSessionKeyRef ?? { current: SESSION_KEY },
        attachments: [],
        busy,
        clearDraft,
        draftRef,
        focusInput: () => undefined,
        loadIntoComposer: () => undefined,
        onCancel,
        onSubmit,
        queueEditRef,
        queueSessionKey: SESSION_KEY,
        sessionId: 'rt-session-queue-hook'
      }),
    { initialProps: { busy: overrides.busy ?? false } }
  )

  return { clearDraft, draftRef, hook, onCancel, onSubmit }
}

describe('useComposerQueue park integration', () => {
  beforeEach(() => {
    window.localStorage.clear()
    $queuedPromptsBySession.set({})
    $parkedQueueSessions.set({})
  })

  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
    contributionDisposers.splice(0).forEach(dispose => dispose())
    $queuedPromptsBySession.set({})
    $parkedQueueSessions.set({})
  })

  it('auto-drains an unparked queue once idle', async () => {
    enqueueQueuedPrompt(SESSION_KEY, { attachments: [], text: 'flows' })

    const { onSubmit } = renderQueueHook()

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(getQueuedPrompts(SESSION_KEY)).toHaveLength(0)
  })

  it('commits middleware once when a busy draft enters the queue and not again on drain', async () => {
    const middlewareContexts: unknown[] = []
    const commit = vi.fn()
    contributionDisposers.push(
      registry.register({
        id: 'test-turn-metadata',
        area: COMPOSER_AREAS.middleware,
        data: {
          handler: (draft, context) => {
            middlewareContexts.push(context)

            return {
              draft: { ...draft, turnMetadata: { 'acme.review': { mode: 'strict' } } },
              onCommit: commit
            }
          }
        } satisfies ComposerMiddleware
      })
    )

    const { hook, onSubmit } = renderQueueHook({ busy: true, text: 'queue with intent' })

    await act(async () => {
      expect(await hook.result.current.queueCurrentDraft()).toBe(true)
    })

    expect(getQueuedPrompts(SESSION_KEY)[0]).toMatchObject({
      text: 'queue with intent',
      composerPrepared: true,
      turnMetadata: { 'acme.review': { mode: 'strict' } }
    })
    expect(middlewareContexts).toEqual([{ runtimeSessionId: 'rt-session-queue-hook', storedSessionId: SESSION_KEY }])
    expect(commit).toHaveBeenCalledTimes(1)

    hook.rerender({ busy: false })
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(commit).toHaveBeenCalledTimes(1)
  })

  it('queues to the captured session without clearing a new session draft after async middleware', async () => {
    let releaseMiddleware!: () => void
    const middlewarePending = new Promise<void>(resolve => (releaseMiddleware = resolve))

    contributionDisposers.push(
      registry.register({
        id: 'test-async-middleware',
        area: COMPOSER_AREAS.middleware,
        data: {
          handler: async draft => {
            await middlewarePending

            return draft
          }
        } satisfies ComposerMiddleware
      })
    )

    const activeQueueSessionKeyRef = { current: SESSION_KEY as string | null }

    const { clearDraft, hook } = renderQueueHook({
      activeQueueSessionKeyRef,
      busy: true,
      text: 'belongs to the old session'
    })

    let queued!: Promise<boolean>
    act(() => {
      queued = hook.result.current.queueCurrentDraft()
      activeQueueSessionKeyRef.current = 'new-session'
      releaseMiddleware()
    })

    await expect(queued).resolves.toBe(true)
    expect(getQueuedPrompts(SESSION_KEY)[0]?.text).toBe('belongs to the old session')
    expect(clearDraft).not.toHaveBeenCalled()
  })

  it('drains the metadata snapshot without dropping its prepared marker', async () => {
    enqueueQueuedPrompt(SESSION_KEY, {
      attachments: [],
      text: 'prepared turn',
      turnMetadata: { 'acme.review': { mode: 'strict' } },
      composerPrepared: true
    })

    const { onSubmit } = renderQueueHook()

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith('prepared turn', {
        attachments: [],
        turnMetadata: { 'acme.review': { mode: 'strict' } },
        composerPrepared: true,
        fromQueue: true,
        sessionId: 'rt-session-queue-hook',
        storedSessionId: SESSION_KEY
      })
    )
  })

  it('holds a parked queue at the idle settle (the Stop edge)', async () => {
    enqueueQueuedPrompt(SESSION_KEY, { attachments: [], text: 'halted' })
    parkQueuedPrompts(SESSION_KEY)

    const { hook, onSubmit } = renderQueueHook({ busy: true })

    // The Stop settle: busy flips false with the park in place.
    hook.rerender({ busy: false })

    await act(async () => {
      await Promise.resolve()
    })

    expect(onSubmit).not.toHaveBeenCalled()
    expect(getQueuedPrompts(SESSION_KEY)).toHaveLength(1)
  })

  it('drainNextQueued sends a parked entry and lifts the park (manual resume)', async () => {
    enqueueQueuedPrompt(SESSION_KEY, { attachments: [], text: 'resumed' })
    parkQueuedPrompts(SESSION_KEY)

    const { hook, onSubmit } = renderQueueHook()

    await act(async () => {
      await hook.result.current.drainNextQueued()
    })

    expect(onSubmit).toHaveBeenCalledTimes(1)
    expect(isQueueParked(SESSION_KEY)).toBe(false)
  })

  it('sendQueuedNow while busy unparks so the settle drain flows (no stale latch)', async () => {
    const first = enqueueQueuedPrompt(SESSION_KEY, { attachments: [], text: 'first' })
    enqueueQueuedPrompt(SESSION_KEY, { attachments: [], text: 'send me now' })
    parkQueuedPrompts(SESSION_KEY)

    const { hook, onCancel, onSubmit } = renderQueueHook({ busy: true })
    const target = getQueuedPrompts(SESSION_KEY).find(e => e.id !== first!.id)!

    act(() => {
      hook.result.current.sendQueuedNow(target.id)
    })

    // The interrupt fired and the park lifted — this interrupt exists to reach
    // the queue, not to halt it.
    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(isQueueParked(SESSION_KEY)).toBe(false)

    // Turn settles → the promoted entry drains.
    hook.rerender({ busy: false })

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect(onSubmit.mock.calls[0]?.[0]).toBe('send me now')
  })
})
