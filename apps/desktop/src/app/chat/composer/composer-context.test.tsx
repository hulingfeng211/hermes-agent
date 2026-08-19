import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { Slot } from '@/contrib/react/slot'
import { registry } from '@/contrib/registry'

import { COMPOSER_AREAS, ComposerContextProvider, type ComposerContextValue, useComposerContext } from './contrib'

const disposers: Array<() => void> = []

afterEach(() => {
  cleanup()
  disposers.splice(0).forEach(dispose => dispose())
})

function ContextProbe() {
  const context = useComposerContext()

  return <output>{`${context.runtimeSessionId ?? 'none'}:${context.storedSessionId ?? 'none'}`}</output>
}

function renderComposerSlot(context: ComposerContextValue) {
  disposers.push(
    registry.register({
      id: 'context-probe',
      area: COMPOSER_AREAS.top,
      render: () => <ContextProbe />
    })
  )

  return render(
    <ComposerContextProvider value={context}>
      <Slot area={COMPOSER_AREAS.top} />
    </ComposerContextProvider>
  )
}

describe('composer contribution context', () => {
  it('scopes a render contribution to its owning ChatBar identity', () => {
    renderComposerSlot({ runtimeSessionId: 'runtime-tile', storedSessionId: 'stored-tile-root' })

    expect(screen.queryByText('runtime-tile:stored-tile-root')).not.toBeNull()
  })

  it('updates a mounted contribution when its ChatBar target changes', () => {
    const view = renderComposerSlot({ runtimeSessionId: 'runtime-a', storedSessionId: 'stored-a' })

    view.rerender(
      <ComposerContextProvider value={{ runtimeSessionId: 'runtime-b', storedSessionId: 'stored-b' }}>
        <Slot area={COMPOSER_AREAS.top} />
      </ComposerContextProvider>
    )

    expect(screen.queryByText('runtime-b:stored-b')).not.toBeNull()
  })
})
