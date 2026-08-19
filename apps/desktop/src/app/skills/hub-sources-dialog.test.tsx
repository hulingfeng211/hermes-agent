import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type * as HermesApi from '@/hermes'

import { HubSourcesDialog } from './hub-sources-dialog'

const getSkillHubConfig = vi.fn()
const saveSkillHubConfig = vi.fn()
const testSkillHubSource = vi.fn()

vi.mock('@/hermes', async importOriginal => ({
  ...(await importOriginal<typeof HermesApi>()),
  getSkillHubConfig: () => getSkillHubConfig(),
  saveSkillHubConfig: (config: unknown) => saveSkillHubConfig(config),
  testSkillHubSource: (source: unknown) => testSkillHubSource(source)
}))

vi.mock('@/store/notifications', () => ({
  notify: vi.fn(),
  notifyError: vi.fn()
}))

function renderDialog() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  })

  return render(
    <QueryClientProvider client={queryClient}>
      <HubSourcesDialog onOpenChange={vi.fn()} open />
    </QueryClientProvider>
  )
}

beforeEach(() => {
  getSkillHubConfig.mockResolvedValue({ mode: 'public', sources: [] })
  saveSkillHubConfig.mockResolvedValue({ ok: true, mode: 'hybrid', sources: [] })
  testSkillHubSource.mockResolvedValue({
    ok: true,
    status: 'online',
    last_error: null,
    last_synced_at: null,
    skill_count: 3
  })
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('HubSourcesDialog', () => {
  it('adds an enterprise source and moves public mode to hybrid', async () => {
    renderDialog()

    await screen.findByText('No enterprise sources configured.')
    fireEvent.click(screen.getByRole('button', { name: 'Add source' }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Corporate Hub' } })
    fireEvent.change(screen.getByLabelText('Index URL'), { target: { value: 'http://skills.corp' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add source' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(saveSkillHubConfig).toHaveBeenCalledWith({
        mode: 'hybrid',
        sources: [
          {
            id: 'skills',
            label: 'Corporate Hub',
            index_url: 'http://skills.corp',
            token_env: '',
            allow_private_network: true,
            ca_bundle: ''
          }
        ]
      })
    )
  })

  it('keeps private mode explicit when no enterprise source is configured', async () => {
    renderDialog()

    await screen.findByText('No enterprise sources configured.')
    fireEvent.click(screen.getByRole('button', { name: 'Enterprise only' }))

    expect(screen.getByText('Public registries are disabled. Local optional skills remain available.')).toBeTruthy()
  })
})
