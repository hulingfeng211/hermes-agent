import { describe, expect, it } from 'vitest'

import { registerPluginLocales } from '@/i18n'

import {
  NEW_CHAT_ROUTE,
  primaryRouteSelectedSessionId,
  sessionRoute,
  SETTINGS_ROUTE,
  sidebarNavContributionLabel
} from './routes'

const SESS_A = 'sess-a'
const SESS_B = 'sess-b'

describe('primaryRouteSelectedSessionId', () => {
  it('prefers the routed session id over a stale/different store selection (#59305)', () => {
    // The route already committed to B while the store selection hasn't
    // caught up yet (still reads A) — the route wins.
    expect(primaryRouteSelectedSessionId(sessionRoute(SESS_B), SESS_A)).toBe(SESS_B)
  })

  it('returns null on the new-chat route even with a leftover selection from the previous chat', () => {
    expect(primaryRouteSelectedSessionId(NEW_CHAT_ROUTE, SESS_A)).toBeNull()
  })

  it('falls back to the store selection on a non-chat route (settings, overlays)', () => {
    expect(primaryRouteSelectedSessionId(SETTINGS_ROUTE, SESS_A)).toBe(SESS_A)
  })

  it('falls back to the store selection when the route matches the same session', () => {
    expect(primaryRouteSelectedSessionId(sessionRoute(SESS_A), SESS_A)).toBe(SESS_A)
  })

  it('returns null on a non-chat route with no store selection', () => {
    expect(primaryRouteSelectedSessionId(SETTINGS_ROUTE, null)).toBeNull()
  })
})

describe('sidebarNavContributionLabel', () => {
  it('resolves a plugin-owned label key against the active locale', () => {
    const dispose = registerPluginLocales('nav-test', {
      en: { navLabel: 'Knowledge Base' },
      zh: { navLabel: '知识库' }
    })

    try {
      expect(
        sidebarNavContributionLabel(
          { source: 'plugin:nav-test' },
          { codicon: 'library', label: 'Knowledge Base', labelKey: 'navLabel', path: '/knowledge' },
          'zh'
        )
      ).toBe('知识库')
    } finally {
      dispose()
    }
  })

  it('uses the plain label when the localized key is unavailable', () => {
    expect(
      sidebarNavContributionLabel(
        { source: 'plugin:missing' },
        { codicon: 'library', label: 'Knowledge Base', labelKey: 'navLabel', path: '/knowledge' },
        'zh'
      )
    ).toBe('Knowledge Base')
  })
})
