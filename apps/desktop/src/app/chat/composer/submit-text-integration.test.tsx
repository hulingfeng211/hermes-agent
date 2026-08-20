import { AssistantRuntimeProvider, type ThreadMessage, useExternalStoreRuntime } from '@assistant-ui/react'
import { act, cleanup, render, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { registry } from '@/contrib/registry'
import { createClientSessionState } from '@/lib/chat-runtime'
import { host } from '@/sdk'
import { $composerAttachments, type ComposerAttachment } from '@/store/composer'
import { clearQueuedPrompts, enqueueQueuedPrompt } from '@/store/composer-queue'
import { $activeGatewayProfile } from '@/store/profile'
import {
  $activeSessionId,
  $connection,
  $gatewayState,
  $selectedStoredSessionId,
  $sessions,
  setBusy
} from '@/store/session'
import { $sessionStates, $sessionTiles } from '@/store/session-states'

import { COMPOSER_AREAS, type ComposerContextValue, type ComposerMiddleware } from './contrib'
import { COMPOSER_SUBMIT_ADMISSION_TIMEOUT_MS } from './focus'
import type { ChatBarProps, ChatBarState } from './types'

import { ChatBar } from '.'

const RUNTIME_ID = 'runtime-session'
const STORED_ID = 'stored-session'
const disposers: Array<() => void> = []

class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

vi.stubGlobal('ResizeObserver', NoopResizeObserver)
vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) =>
  window.setTimeout(() => callback(performance.now()), 0)
)
vi.stubGlobal('cancelAnimationFrame', (id: number) => window.clearTimeout(id))

const CHAT_BAR_STATE: ChatBarState = {
  model: { canSwitch: false, model: '', provider: '' },
  tools: { enabled: true, label: 'Add context' },
  voice: { active: false, enabled: false }
}

function RuntimeBoundary({ children }: { children: ReactNode }) {
  const runtime = useExternalStoreRuntime<ThreadMessage>({
    isRunning: false,
    messages: [],
    onNew: async () => {}
  })

  return <AssistantRuntimeProvider runtime={runtime}>{children}</AssistantRuntimeProvider>
}

function renderChatBar(onSubmit: ChatBarProps['onSubmit']) {
  return render(
    <RuntimeBoundary>
      <MemoryRouter>
        <ChatBar
          busy={false}
          disabled={false}
          onCancel={() => {}}
          onSubmit={onSubmit}
          queueSessionKey={STORED_ID}
          sessionId={RUNTIME_ID}
          state={CHAT_BAR_STATE}
        />
      </MemoryRouter>
    </RuntimeBoundary>
  )
}

function addMiddleware(handler: ComposerMiddleware['handler']) {
  disposers.push(
    registry.register({
      area: COMPOSER_AREAS.middleware,
      data: { handler } satisfies ComposerMiddleware,
      id: `submit-text-test-${disposers.length}`
    })
  )
}

function target() {
  return {
    connectionId: null,
    profile: 'default',
    runtimeSessionId: RUNTIME_ID,
    storedSessionId: STORED_ID
  }
}

function deferred() {
  let resolve!: () => void

  const promise = new Promise<void>(done => {
    resolve = done
  })

  return { promise, resolve }
}

function commitSubmit(options: Parameters<ChatBarProps['onSubmit']>[1]): boolean {
  if (options?.composerAdmission && !options.composerAdmission.commit()) {
    return false
  }

  options?.commitComposerAdmission?.()

  return true
}

beforeEach(() => {
  $activeGatewayProfile.set('default')
  $activeSessionId.set(RUNTIME_ID)
  $selectedStoredSessionId.set(STORED_ID)
  $sessions.set([])
  $sessionTiles.set([])
  $sessionStates.set({ [RUNTIME_ID]: createClientSessionState(STORED_ID) })
  $connection.set(null)
  $gatewayState.set('open')
  setBusy(false)
  clearQueuedPrompts(STORED_ID)
  $composerAttachments.set([])
})

afterEach(() => {
  cleanup()
  disposers.splice(0).forEach(dispose => dispose())
  clearQueuedPrompts(STORED_ID)
  $composerAttachments.set([])
  $sessionStates.set({})
  $sessionTiles.set([])
  $activeSessionId.set(null)
  $selectedStoredSessionId.set(null)
  $connection.set(null)
  $gatewayState.set('idle')
  $activeGatewayProfile.set('default')
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('host.submitText through the real ChatBar middleware boundary', () => {
  it('carries the full backend context and preserves an explicit empty attachment set', async () => {
    const draftAttachment: ComposerAttachment = { id: 'draft', kind: 'file', label: 'draft.txt' }
    const contexts: ComposerContextValue[] = []
    const committed = vi.fn()
    const onSubmit = vi.fn<ChatBarProps['onSubmit']>(async (_text, options) => commitSubmit(options))

    addMiddleware((draft, context) => {
      contexts.push(context)

      // Deliberately omit attachments: the external [] must survive.
      return { draft: { text: `${draft.text} rewritten` }, onCommit: committed }
    })
    renderChatBar(onSubmit)
    act(() => $composerAttachments.set([draftAttachment]))

    await expect(host.submitText('question', target())).resolves.toBe(true)

    expect(contexts).toEqual([
      {
        connectionId: null,
        profile: 'default',
        runtimeSessionId: RUNTIME_ID,
        storedSessionId: STORED_ID
      }
    ])
    expect(onSubmit).toHaveBeenCalledWith(
      'question rewritten',
      expect.objectContaining({ attachments: [], sessionId: RUNTIME_ID, storedSessionId: STORED_ID })
    )
    expect($composerAttachments.get()).toEqual([draftAttachment])
    expect(committed).toHaveBeenCalledTimes(1)
  })

  it('keeps the original two-id target source-compatible by snapshotting the current backend at call time', async () => {
    const onSubmit = vi.fn<ChatBarProps['onSubmit']>(async (_text, options) => commitSubmit(options))

    renderChatBar(onSubmit)

    await expect(
      host.submitText('legacy question', { runtimeSessionId: RUNTIME_ID, storedSessionId: STORED_ID })
    ).resolves.toBe(true)
    expect(onSubmit).toHaveBeenCalledWith('legacy question', expect.objectContaining({ attachments: [] }))
  })

  it.each([
    ['profile', { ...target(), profile: 'other-profile' }],
    ['connection', { ...target(), connectionId: 'other-backend' }]
  ])('rejects a colliding session-id pair from a different %s', async (_label, staleTarget) => {
    const middleware = vi.fn<ComposerMiddleware['handler']>(draft => draft)
    const onSubmit = vi.fn<ChatBarProps['onSubmit']>(async () => true)

    addMiddleware(middleware)
    renderChatBar(onSubmit)

    await expect(host.submitText('wrong backend', staleTarget)).resolves.toBe(false)
    expect(middleware).not.toHaveBeenCalled()
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it.each([
    [
      'the addressed session becoming busy',
      () => $sessionStates.set({ [RUNTIME_ID]: { ...createClientSessionState(STORED_ID), busy: true } })
    ],
    ['a queued prompt', () => enqueueQueuedPrompt(STORED_ID, { attachments: [], text: 'already waiting' })],
    ['a reconnect', () => $gatewayState.set('connecting')],
    [
      'a target switch',
      () => {
        $activeSessionId.set('runtime-other')
        $selectedStoredSessionId.set('stored-other')
      }
    ],
    ['a profile switch', () => $activeGatewayProfile.set('other-profile')],
    [
      'a connection switch',
      () =>
        $connection.set({
          baseUrl: 'https://other.invalid',
          connectionId: 'other-backend',
          isFullscreen: false,
          mode: 'remote',
          nativeOverlayWidth: 0,
          token: '',
          windowButtonPosition: null,
          wsUrl: 'wss://other.invalid/ws',
          logs: []
        })
    ]
  ])('cancels a claimed submit when middleware races %s', async (_label, invalidate) => {
    const gate = deferred()
    const entered = vi.fn()
    const committed = vi.fn()
    const onSubmit = vi.fn<ChatBarProps['onSubmit']>(async () => true)

    addMiddleware(async draft => {
      entered()
      await gate.promise

      return { draft, onCommit: committed }
    })
    renderChatBar(onSubmit)

    const submission = host.submitText('question', target())
    await waitFor(() => expect(entered).toHaveBeenCalledTimes(1))

    act(invalidate)
    await expect(submission).resolves.toBe(false)

    gate.resolve()
    await act(async () => Promise.resolve())
    expect(onSubmit).not.toHaveBeenCalledWith('question', expect.anything())
    expect(committed).not.toHaveBeenCalled()
  })

  it.each([
    ['a queued prompt', () => enqueueQueuedPrompt(STORED_ID, { attachments: [], text: 'already waiting' })],
    ['a reconnect', () => $gatewayState.set('connecting')],
    [
      'a target switch',
      () => {
        $activeSessionId.set('runtime-other')
        $selectedStoredSessionId.set('stored-other')
      }
    ],
    ['a profile switch', () => $activeGatewayProfile.set('other-profile')],
    [
      'a connection switch',
      () =>
        $connection.set({
          baseUrl: 'https://other.invalid',
          connectionId: 'other-backend',
          isFullscreen: false,
          mode: 'remote',
          nativeOverlayWidth: 0,
          token: '',
          windowButtonPosition: null,
          wsUrl: 'wss://other.invalid/ws',
          logs: []
        })
    ]
  ])('cancels native submit preparation when it races %s', async (_label, invalidate) => {
    const gate = deferred()
    const entered = vi.fn()
    const gatewaySend = vi.fn()
    const committed = vi.fn()

    const onSubmit = vi.fn<ChatBarProps['onSubmit']>(async (text, options) => {
      if (text !== 'question') {
        return false
      }

      entered()
      await gate.promise

      const accepted = commitSubmit(options)

      if (accepted) {
        gatewaySend()
      }

      return accepted
    })

    addMiddleware(draft => ({ draft, onCommit: committed }))
    renderChatBar(onSubmit)

    const submission = host.submitText('question', target())
    await waitFor(() => expect(entered).toHaveBeenCalledTimes(1))

    act(invalidate)
    await expect(submission).resolves.toBe(false)

    gate.resolve()
    await act(async () => Promise.resolve())
    expect(gatewaySend).not.toHaveBeenCalled()
    expect(committed).not.toHaveBeenCalled()
  })

  it('cancels a claimed submit when its ChatBar is disposed and never sends late', async () => {
    const gate = deferred()
    const entered = vi.fn()
    const committed = vi.fn()
    const onSubmit = vi.fn<ChatBarProps['onSubmit']>(async () => true)

    addMiddleware(async draft => {
      entered()
      await gate.promise

      return { draft, onCommit: committed }
    })
    const view = renderChatBar(onSubmit)

    const submission = host.submitText('question', target())
    await waitFor(() => expect(entered).toHaveBeenCalledTimes(1))

    view.unmount()
    await expect(submission).resolves.toBe(false)

    gate.resolve()
    await act(async () => Promise.resolve())
    expect(onSubmit).not.toHaveBeenCalled()
    expect(committed).not.toHaveBeenCalled()
  })

  it('bounds a hung middleware claim and cannot send after the deadline', async () => {
    const gate = deferred()
    const entered = vi.fn()
    const committed = vi.fn()
    const onSubmit = vi.fn<ChatBarProps['onSubmit']>(async () => true)

    addMiddleware(async draft => {
      entered()
      await gate.promise

      return { draft, onCommit: committed }
    })
    renderChatBar(onSubmit)
    vi.useFakeTimers()

    const submission = host.submitText('question', target())
    await act(async () => vi.advanceTimersByTimeAsync(0))
    expect(entered).toHaveBeenCalledTimes(1)

    await act(async () => vi.advanceTimersByTimeAsync(COMPOSER_SUBMIT_ADMISSION_TIMEOUT_MS))
    await expect(submission).resolves.toBe(false)

    gate.resolve()
    await act(async () => Promise.resolve())
    expect(onSubmit).not.toHaveBeenCalled()
    expect(committed).not.toHaveBeenCalled()
  })
})
