import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { onComposerSubmitRequest } from '@/app/chat/composer/focus'
import { createClientSessionState } from '@/lib/chat-runtime'
import { $queuedPromptsBySession } from '@/store/composer-queue'
import { $gatewayState, setActiveSessionId, setSelectedStoredSessionId } from '@/store/session'
import { $sessionStates, $sessionTiles, dropSessionState, publishSessionState } from '@/store/session-states'

import { host } from './index'

// Plugins read app state exclusively through host.state — and before this
// contract existed, only the PRIMARY workspace tab was reachable
// ($activeSessionId). Clicking a tile never moved any plugin-visible atom,
// and tile focus is pure renderer state that gateway RPC can never see, so
// no plugin-side workaround was possible. These atoms are the plugin door to
// the same focused-session signals the core statusbar reads
// (use-statusbar-items.tsx).

describe('host.state focused-session atoms', () => {
  beforeEach(() => {
    window.localStorage.clear()
    vi.resetModules()
  })

  afterEach(() => {
    vi.resetModules()
  })

  async function setup() {
    const { host } = await import('@/sdk/index')
    const states = await import('@/store/session-states')
    const session = await import('@/store/session')

    return { host, states, session }
  }

  it('exposes readonly atoms for the focused session (runtime id, stored id, usage)', async () => {
    const { host } = await setup()

    for (const key of ['focusedSessionId', 'focusedStoredSessionId', 'focusedUsage'] as const) {
      const store = host.state[key]
      expect(store, key).toBeDefined()
      expect(typeof store.get, key).toBe('function')
      expect(typeof store.listen, key).toBe('function')
      expect(typeof store.subscribe, key).toBe('function')
    }
  })

  it('mirrors the primary session while no tile is focused', async () => {
    const { host, states } = await setup()

    expect(host.state.focusedSessionId.get()).toBe(states.$focusedRuntimeId.get())
    expect(host.state.focusedStoredSessionId.get()).toBe(states.$focusedStoredSessionId.get())
  })

  it('focusedUsage projects the focused session usage, null while unresolved', async () => {
    const { host, states } = await setup()

    const focused = states.$focusedSessionState.get()
    expect(host.state.focusedUsage.get()).toBe(focused?.usage ?? null)
  })

  it('exposes the registry source that owns the active gateway', async () => {
    const { host, session } = await setup()

    session.setConnection({ connectionId: 'work', mode: 'remote' } as never)
    expect(host.state.connectionId.get()).toBe('work')

    session.setConnection({ mode: 'local' } as never)
    expect(host.state.connectionId.get()).toBe('local')
    session.setConnection(null)
  })

  it('follows the interacted tile while the primary-only atom stays put', async () => {
    const { host, session, states } = await setup()
    const tree = await import('@/components/pane-shell/tree/store')
    const model = await import('@/components/pane-shell/tree/model')
    const { registry } = await import('@/contrib/registry')

    // A second chat zone holding a session tile, next to the main workspace.
    for (const id of ['workspace', 'session-tile:tile-a']) {
      registry.register({
        area: 'panes',
        data: id === 'workspace' ? { placement: 'main', uncloseable: true } : { placement: 'main' },
        id,
        render: () => null,
        title: id
      })
    }

    tree.declareDefaultTree(
      model.split('row', [
        model.group(['workspace'], { active: 'workspace', id: 'grp-main' }),
        model.group(['session-tile:tile-a'], { active: 'session-tile:tile-a', id: 'grp-side' })
      ])
    )

    const primaryBefore = session.$activeSessionId.get()
    const primarySelection = session.$selectedStoredSessionId.get()

    // Bind the tile to a live runtime with its own usage, so the readout
    // atoms (focusedSessionId / focusedUsage) — not just the navigation id —
    // are proven to follow the tile.
    const tileUsage = {
      calls: 3,
      input: 1200,
      output: 300,
      total: 1500,
      context_used: 42000,
      context_max: 200000,
      context_percent: 21,
      cost_usd: 0.0123
    }

    states.$sessionTiles.set([{ storedSessionId: 'tile-a', runtimeId: 'runtime-tile-a' }])
    states.$sessionStates.set({
      'runtime-tile-a': { storedSessionId: 'tile-a', usage: tileUsage } as never
    })

    // Focusing the tile zone moves the focused atoms onto the tile's session…
    tree.noteActiveTreeGroup('grp-side')
    expect(host.state.focusedStoredSessionId.get()).toBe('tile-a')
    expect(host.state.focusedSessionId.get()).toBe('runtime-tile-a')
    expect(host.state.focusedUsage.get()).toBe(tileUsage)
    // …while the primary-only atom a plugin used to rely on does not move.
    expect(host.state.activeSessionId.get()).toBe(primaryBefore)

    // Focusing back homes to the primary's selection, whatever it is.
    tree.noteActiveTreeGroup('grp-main')
    expect(host.state.focusedStoredSessionId.get()).toBe(primarySelection)
  })
})

describe('host.state busy vs gateway', () => {
  afterEach(() => {
    $sessionStates.set({})
    $sessionTiles.set([])
    $queuedPromptsBySession.set({})
    setActiveSessionId(null)
    setSelectedStoredSessionId(null)
    $gatewayState.set('idle')
  })

  it('exposes per-session turn-busy and does not treat gateway as busy', () => {
    const running = { ...createClientSessionState('stored-a'), busy: true }
    const idle = { ...createClientSessionState('stored-b'), busy: false }

    publishSessionState('runtime-a', running)
    publishSessionState('runtime-b', idle)
    $gatewayState.set('open')

    expect(host.state.busyBySession.get()).toEqual({ 'runtime-a': true, 'runtime-b': false })
    expect(host.state.gateway.get()).toBe('open')

    dropSessionState('runtime-a')
    expect(host.state.busyBySession.get()['runtime-a']).toBeUndefined()
    expect(host.state.gateway.get()).toBe('open')
  })

  it('exposes non-empty composer queue counts by durable session key', () => {
    $queuedPromptsBySession.set({
      'stored-a': [
        { id: 'queued-1', text: 'first', attachments: [], queuedAt: 1 },
        { id: 'queued-2', text: 'second', attachments: [], queuedAt: 2 }
      ],
      'stored-empty': []
    })

    expect(host.state.queuedPromptCountBySession.get()).toEqual({ 'stored-a': 2 })

    $queuedPromptsBySession.set({})
    expect(host.state.queuedPromptCountBySession.get()).toEqual({})
  })

  it('submits only to the exact main or tile composer identity', async () => {
    const targets: string[] = []

    $gatewayState.set('open')

    const off = onComposerSubmitRequest(detail => {
      if (!detail.claim()) {
        return
      }

      targets.push(detail.target)
      detail.resolve(true)
    })

    setActiveSessionId('runtime-main')
    setSelectedStoredSessionId('stored-main')
    $sessionTiles.set([{ runtimeId: 'runtime-tile', storedSessionId: 'stored-tile' }])

    await expect(
      host.submitText('partial identity', {
        runtimeSessionId: 'runtime-main',
        storedSessionId: null
      })
    ).resolves.toBe(false)

    publishSessionState('runtime-main', { ...createClientSessionState('stored-main'), busy: true })
    await expect(
      host.submitText('busy question', {
        runtimeSessionId: 'runtime-main',
        storedSessionId: 'stored-main'
      })
    ).resolves.toBe(false)
    dropSessionState('runtime-main')

    $queuedPromptsBySession.set({
      'stored-main': [{ id: 'queued-1', text: 'first', attachments: [], queuedAt: 1 }]
    })
    await expect(
      host.submitText('out-of-order question', {
        runtimeSessionId: 'runtime-main',
        storedSessionId: 'stored-main'
      })
    ).resolves.toBe(false)
    $queuedPromptsBySession.set({})

    await expect(
      host.submitText('main question', {
        runtimeSessionId: 'runtime-main',
        storedSessionId: 'stored-main'
      })
    ).resolves.toBe(true)
    await expect(
      host.submitText('tile question', {
        runtimeSessionId: 'runtime-tile',
        storedSessionId: 'stored-tile'
      })
    ).resolves.toBe(true)

    $sessionTiles.set([
      { runtimeId: 'runtime-tile', storedSessionId: 'stored-tile' },
      { runtimeId: 'runtime-main', storedSessionId: 'stored-main' }
    ])
    await expect(
      host.submitText('ambiguous surface', {
        runtimeSessionId: 'runtime-main',
        storedSessionId: 'stored-main'
      })
    ).resolves.toBe(false)

    await expect(
      host.submitText('stale question', {
        runtimeSessionId: 'runtime-stale',
        storedSessionId: 'stored-main'
      })
    ).resolves.toBe(false)

    expect(targets).toEqual(['main', 'tile:stored-tile'])
    off()
  })
})
