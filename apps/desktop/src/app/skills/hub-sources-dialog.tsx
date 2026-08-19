import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@/components/ui/dialog'
import { Field, FieldHint } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { SegmentedControl } from '@/components/ui/segmented-control'
import { Switch } from '@/components/ui/switch'
import {
  type EnterpriseSkillHubSourceConfig,
  getSkillHubConfig,
  type ProfileScope,
  profileScopeKey,
  saveSkillHubConfig,
  type SkillHubMode,
  type SkillHubSourceProbeResponse,
  testSkillHubSource
} from '@/hermes'
import { useI18n } from '@/i18n'
import { CheckCircle2, Loader2, Pencil, Plus, RefreshCw, Trash2 } from '@/lib/icons'
import { HUB_SOURCES_KEY } from '@/store/hub-actions'
import { notify, notifyError } from '@/store/notifications'

const HUB_CONFIG_KEY = ['skill-hub-config'] as const

interface HubSourcesDialogProps {
  onOpenChange: (open: boolean) => void
  open: boolean
  profile?: ProfileScope
}

interface SourceDraft {
  allowPrivateNetwork: boolean
  caBundle: string
  id: string
  indexUrl: string
  label: string
  tokenEnv: string
}

function emptyDraft(): SourceDraft {
  return {
    allowPrivateNetwork: true,
    caBundle: '',
    id: '',
    indexUrl: '',
    label: '',
    tokenEnv: ''
  }
}

function sourceId(label: string, indexUrl: string, existing: EnterpriseSkillHubSourceConfig[]): string {
  let seed = ''

  try {
    seed = new URL(indexUrl).hostname.split('.')[0] || ''
  } catch {
    // Validation below owns malformed URLs.
  }

  seed = (seed || label)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)

  if (!/^[a-z]/.test(seed)) {
    seed = `hub-${seed || 'internal'}`
  }

  let candidate = seed
  let suffix = 2

  while (existing.some(source => source.id === candidate)) {
    candidate = `${seed.slice(0, 43)}-${suffix}`
    suffix += 1
  }

  return candidate
}

function toSource(draft: SourceDraft, existing: EnterpriseSkillHubSourceConfig[]): EnterpriseSkillHubSourceConfig {
  return {
    id: draft.id || sourceId(draft.label, draft.indexUrl, existing),
    label: draft.label.trim(),
    index_url: draft.indexUrl.trim(),
    token_env: draft.tokenEnv.trim(),
    allow_private_network: draft.allowPrivateNetwork,
    ca_bundle: draft.caBundle.trim()
  }
}

function probeTone(status?: SkillHubSourceProbeResponse['status']): string {
  if (status === 'online') {
    return 'text-emerald-400'
  }

  if (status === 'cached') {
    return 'text-amber-400'
  }

  return 'text-destructive'
}

export function HubSourcesDialog({ onOpenChange, open, profile }: HubSourcesDialogProps) {
  const { t } = useI18n()
  const h = t.skills.hub.sources
  const queryClient = useQueryClient()
  const scopeKey = profileScopeKey(profile)

  const configQuery = useQuery({
    queryKey: [...HUB_CONFIG_KEY, scopeKey],
    queryFn: () => getSkillHubConfig(profile),
    enabled: open,
    staleTime: 30_000
  })

  const [mode, setMode] = useState<SkillHubMode>('public')
  const [sources, setSources] = useState<EnterpriseSkillHubSourceConfig[]>([])
  const [draft, setDraft] = useState<SourceDraft>(emptyDraft)
  const [showForm, setShowForm] = useState(false)
  const [formError, setFormError] = useState('')
  const [saving, setSaving] = useState(false)
  const [probingId, setProbingId] = useState<null | string>(null)
  const [probeResults, setProbeResults] = useState<Record<string, SkillHubSourceProbeResponse>>({})

  useEffect(() => {
    if (!open || !configQuery.data) {
      return
    }
    setMode(configQuery.data.mode)
    setSources(configQuery.data.sources)
    setDraft(emptyDraft())
    setShowForm(false)
    setFormError('')
    setProbeResults({})
  }, [configQuery.data, open])

  const modeOptions = useMemo(
    () => [
      { id: 'public' as const, label: h.modePublic },
      { id: 'hybrid' as const, label: h.modeHybrid },
      { id: 'private' as const, label: h.modePrivate }
    ],
    [h]
  )

  const edit = (source: EnterpriseSkillHubSourceConfig) => {
    setDraft({
      allowPrivateNetwork: source.allow_private_network,
      caBundle: source.ca_bundle,
      id: source.id,
      indexUrl: source.index_url,
      label: source.label,
      tokenEnv: source.token_env
    })
    setFormError('')
    setShowForm(true)
  }

  const validateDraft = (): EnterpriseSkillHubSourceConfig | null => {
    if (!draft.label.trim()) {
      setFormError(h.nameRequired)

      return null
    }

    try {
      const parsed = new URL(draft.indexUrl.trim())

      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
        throw new Error('invalid')
      }
    } catch {
      setFormError(h.urlInvalid)

      return null
    }

    if (draft.tokenEnv && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(draft.tokenEnv)) {
      setFormError(h.tokenEnvInvalid)

      return null
    }

    setFormError('')

    return toSource(
      draft,
      sources.filter(source => source.id !== draft.id)
    )
  }

  const upsertDraft = () => {
    const source = validateDraft()

    if (!source) {
      return
    }

    setSources(current => {
      const index = current.findIndex(item => item.id === draft.id)

      if (index < 0) {
        return [...current, source]
      }

      const next = [...current]
      next[index] = source

      return next
    })

    if (mode === 'public') {
      setMode('hybrid')
    }
    setDraft(emptyDraft())
    setShowForm(false)
  }

  const probe = async (source: EnterpriseSkillHubSourceConfig, key: string) => {
    setProbingId(key)

    try {
      const result = await testSkillHubSource(source, profile)
      setProbeResults(current => ({ ...current, [key]: result }))
    } catch (error) {
      notifyError(error, h.testFailed)
    } finally {
      setProbingId(null)
    }
  }

  const probeDraft = () => {
    const source = validateDraft()

    if (source) {
      void probe(source, '__draft__')
    }
  }

  const save = async () => {
    setSaving(true)

    try {
      await saveSkillHubConfig({ mode, sources }, profile)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: [...HUB_CONFIG_KEY, scopeKey] }),
        queryClient.invalidateQueries({ queryKey: HUB_SOURCES_KEY })
      ])
      notify({ kind: 'success', message: h.saved })
      onOpenChange(false)
    } catch (error) {
      notifyError(error, h.saveFailed)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent bodyClassName="min-h-0 overflow-y-auto" className="max-h-[84vh] max-w-2xl">
        <DialogHeader>
          <DialogTitle>{h.title}</DialogTitle>
          <DialogDescription>{h.subtitle}</DialogDescription>
        </DialogHeader>

        {configQuery.isLoading ? (
          <div className="grid min-h-36 place-items-center">
            <Loader2 className="size-4 animate-spin text-muted-foreground" />
          </div>
        ) : configQuery.isError ? (
          <div className="flex min-h-28 items-center justify-center gap-2 text-xs text-destructive">
            <span>{h.loadFailed}</span>
            <Button onClick={() => void configQuery.refetch()} size="inline" variant="textStrong">
              {h.retry}
            </Button>
          </div>
        ) : (
          <div className="grid gap-5">
            <div className="grid gap-2">
              <span className="text-xs font-medium text-foreground">{h.networkMode}</span>
              <SegmentedControl className="max-w-full" onChange={setMode} options={modeOptions} value={mode} />
              {mode === 'private' && <FieldHint>{h.privateModeActive}</FieldHint>}
            </div>

            <div className="grid gap-2">
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-medium text-foreground">{h.enterpriseSources}</span>
                {!showForm && (
                  <Button
                    onClick={() => {
                      setDraft(emptyDraft())
                      setFormError('')
                      setShowForm(true)
                    }}
                    size="xs"
                    variant="textStrong"
                  >
                    <Plus />
                    {h.add}
                  </Button>
                )}
              </div>

              {sources.length === 0 && !showForm ? (
                <p className="py-5 text-center text-xs text-muted-foreground">{h.none}</p>
              ) : (
                <div className="divide-y divide-(--ui-stroke-tertiary)">
                  {sources.map(source => {
                    const result = probeResults[source.id]

                    return (
                      <div className="flex min-w-0 items-center gap-3 py-2.5" key={source.id}>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-xs font-medium text-foreground">{source.label}</div>
                          <div className="truncate font-mono text-[0.64rem] text-muted-foreground">
                            {source.index_url}
                          </div>
                          {result && (
                            <div className={`mt-0.5 text-[0.64rem] ${probeTone(result.status)}`}>
                              {result.status === 'online'
                                ? h.online(result.skill_count)
                                : result.status === 'cached'
                                  ? h.cached(result.skill_count)
                                  : h.unreachable}
                            </div>
                          )}
                        </div>
                        <div className="flex shrink-0 items-center gap-0.5">
                          <Button
                            aria-label={h.test}
                            disabled={probingId !== null}
                            onClick={() => void probe(source, source.id)}
                            size="icon-xs"
                            variant="ghost"
                          >
                            {probingId === source.id ? <Loader2 className="animate-spin" /> : <RefreshCw />}
                          </Button>
                          <Button aria-label={h.edit} onClick={() => edit(source)} size="icon-xs" variant="ghost">
                            <Pencil />
                          </Button>
                          <Button
                            aria-label={h.remove}
                            className="hover:text-destructive"
                            onClick={() => setSources(current => current.filter(item => item.id !== source.id))}
                            size="icon-xs"
                            variant="ghost"
                          >
                            <Trash2 />
                          </Button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {showForm && (
              <div className="grid gap-4 border-t border-(--ui-stroke-tertiary) pt-4">
                <div className="grid items-start gap-4 sm:grid-cols-2">
                  <Field htmlFor="hub-source-name" label={h.name}>
                    <Input
                      id="hub-source-name"
                      onChange={event => setDraft(current => ({ ...current, label: event.target.value }))}
                      placeholder={h.namePlaceholder}
                      value={draft.label}
                    />
                  </Field>
                  <Field htmlFor="hub-source-url" label={h.indexUrl}>
                    <Input
                      id="hub-source-url"
                      onChange={event => setDraft(current => ({ ...current, indexUrl: event.target.value }))}
                      placeholder="https://skills.corp"
                      value={draft.indexUrl}
                    />
                  </Field>
                  <Field htmlFor="hub-source-token" label={h.tokenEnv} optional optionalLabel={h.optional}>
                    <Input
                      id="hub-source-token"
                      onChange={event => setDraft(current => ({ ...current, tokenEnv: event.target.value }))}
                      placeholder="CORP_SKILLHUB_TOKEN"
                      value={draft.tokenEnv}
                    />
                  </Field>
                  <Field htmlFor="hub-source-ca" label={h.caBundle} optional optionalLabel={h.optional}>
                    <Input
                      id="hub-source-ca"
                      onChange={event => setDraft(current => ({ ...current, caBundle: event.target.value }))}
                      placeholder="/etc/ssl/corp-ca.pem"
                      value={draft.caBundle}
                    />
                  </Field>
                </div>

                <label className="flex items-center justify-between gap-4 text-xs text-foreground">
                  <span>{h.allowPrivate}</span>
                  <Switch
                    checked={draft.allowPrivateNetwork}
                    onCheckedChange={checked => setDraft(current => ({ ...current, allowPrivateNetwork: checked }))}
                    size="xs"
                  />
                </label>

                {formError && <FieldHint error>{formError}</FieldHint>}
                {probeResults.__draft__ && (
                  <div className={`flex items-center gap-1.5 text-xs ${probeTone(probeResults.__draft__.status)}`}>
                    {probeResults.__draft__.ok && <CheckCircle2 className="size-3.5" />}
                    {probeResults.__draft__.status === 'online'
                      ? h.online(probeResults.__draft__.skill_count)
                      : probeResults.__draft__.status === 'cached'
                        ? h.cached(probeResults.__draft__.skill_count)
                        : h.unreachable}
                  </div>
                )}

                <div className="flex justify-end gap-2">
                  <Button
                    onClick={() => {
                      setDraft(emptyDraft())
                      setShowForm(false)
                    }}
                    size="sm"
                    variant="text"
                  >
                    {h.cancel}
                  </Button>
                  <Button disabled={probingId !== null} onClick={probeDraft} size="sm" variant="outline">
                    {probingId === '__draft__' && <Loader2 className="animate-spin" />}
                    {h.test}
                  </Button>
                  <Button onClick={upsertDraft} size="sm">
                    {draft.id ? h.update : h.add}
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}

        <DialogFooter>
          <Button onClick={() => onOpenChange(false)} size="sm" variant="text">
            {h.cancel}
          </Button>
          <Button
            disabled={saving || configQuery.isLoading || configQuery.isError}
            onClick={() => void save()}
            size="sm"
          >
            {saving && <Loader2 className="animate-spin" />}
            {saving ? h.saving : h.save}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
