import {
  Button,
  cn,
  Codicon,
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  type HermesPlugin,
  host,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Tip,
  useQuery,
  useValue
} from '@hermes/plugin-sdk'
import { useMemo, useState } from 'react'

type Workspace = {
  workspace_id: string
  name: string
  slug?: string
  kind?: string
}

type WorkspaceResponse = {
  success?: boolean
  workspaces?: Workspace[]
  selected_workspace_id?: string | null
  error?: string
}

type CommandResponse = {
  output?: string
  error?: { message?: string }
}

const WORKSPACES_KEY = ['sws-knowbase', 'workspaces']

function parsePluginOutput(value: unknown): Record<string, unknown> {
  if (typeof value !== 'string') {
    return {}
  }

  try {
    const parsed = JSON.parse(value)

    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

async function runCommand(command: string, sessionId?: string): Promise<CommandResponse> {
  return host.request<CommandResponse>('command.dispatch', {
    name: command.split(' ', 1)[0],
    arg: command.split(' ').slice(1).join(' '),
    ...(sessionId ? { session_id: sessionId } : {})
  })
}

async function fetchWorkspaces(sessionId?: string): Promise<WorkspaceResponse> {
  const response = await runCommand('kb list', sessionId)
  const output = parsePluginOutput(response.output)

  return {
    success: output.success as boolean | undefined,
    workspaces: (output.workspaces as Workspace[] | undefined) ?? [],
    selected_workspace_id: (output.selected_workspace_id as string | null | undefined) ?? null,
    error: (output.error as string | undefined) ?? response.error?.message
  }
}

function KnowledgeWorkspacePicker() {
  const sessionId = useValue(host.state.activeSessionId)
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const { data, isLoading, refetch } = useQuery({
    queryKey: [...WORKSPACES_KEY, sessionId ?? 'draft'],
    queryFn: () => fetchWorkspaces(sessionId ?? undefined),
    staleTime: 30_000,
    enabled: open || Boolean(sessionId)
  })

  const workspaces = useMemo(() => data?.workspaces ?? [], [data?.workspaces])
  const effectiveSelectedId = selectedId ?? data?.selected_workspace_id ?? null
  const selected = workspaces.find(workspace => workspace.workspace_id === effectiveSelectedId)

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()

    if (!needle) {
      return workspaces
    }

    return workspaces.filter(workspace =>
      [workspace.name, workspace.slug, workspace.workspace_id].some(value => value?.toLowerCase().includes(needle))
    )
  }, [query, workspaces])

  const select = async (workspace: Workspace | null) => {
    setPending(true)

    try {
      const response = await runCommand(`kb use ${workspace?.workspace_id ?? ''}`, sessionId ?? undefined)
      const output = parsePluginOutput(response.output)

      if (output.success === false) {
        throw new Error(String(output.error ?? 'Knowledge workspace selection failed'))
      }

      setSelectedId(workspace?.workspace_id ?? null)
      setOpen(false)
      setQuery('')
      await refetch()
    } catch (error) {
      host.notify({ kind: 'error', message: error instanceof Error ? error.message : String(error) })
    } finally {
      setPending(false)
    }
  }

  return (
    <Popover onOpenChange={setOpen} open={open}>
      <Tip label="Choose the knowledge workspace for this conversation">
        <PopoverTrigger asChild>
          <Button
            aria-label="Current knowledge workspace"
            className={cn('h-7 max-w-56 justify-start px-2 text-[0.6875rem]', !selected && 'text-muted-foreground')}
            disabled={pending}
            size="sm"
            variant="ghost"
          >
            <Codicon name="library" />
            <span className="truncate">{selected?.name ?? 'Current space'}</span>
            <Codicon className="ml-auto opacity-60" name={open ? 'chevron-up' : 'chevron-down'} />
          </Button>
        </PopoverTrigger>
      </Tip>
      <PopoverContent align="start" className="w-80 p-0">
        <Command shouldFilter={false}>
          <CommandInput onValueChange={setQuery} placeholder="Filter knowledge workspaces" value={query} />
          <CommandList>
            <CommandEmpty>{isLoading ? 'Loading workspaces…' : 'No matching workspaces'}</CommandEmpty>
            <CommandGroup>
              <CommandItem onSelect={() => void select(null)} value="__none__">
                <Codicon
                  className={cn('size-4', effectiveSelectedId === null ? 'opacity-100' : 'opacity-0')}
                  name="check"
                />
                <span>None selected</span>
              </CommandItem>
              {filtered.map(workspace => (
                <CommandItem
                  key={workspace.workspace_id}
                  onSelect={() => void select(workspace)}
                  value={workspace.workspace_id}
                >
                  <Codicon
                    className={cn(
                      'size-4',
                      workspace.workspace_id === effectiveSelectedId ? 'opacity-100' : 'opacity-0'
                    )}
                    name="check"
                  />
                  <span className="min-w-0 truncate">{workspace.name}</span>
                  {workspace.slug && (
                    <span className="ml-auto max-w-28 truncate text-[0.625rem] text-muted-foreground">
                      {workspace.slug}
                    </span>
                  )}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

const plugin: HermesPlugin = {
  id: 'sws-knowbase',
  name: 'SWS Knowbase',
  defaultEnabled: true,
  register(ctx) {
    ctx.register({
      id: 'workspace-picker',
      area: 'composer.top',
      order: 20,
      render: () => <KnowledgeWorkspacePicker />
    })
  }
}

export default plugin
