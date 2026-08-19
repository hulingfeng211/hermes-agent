/**
 * Composer contribution surface — every seam of the composer is hook-into-able
 * through the SAME registry schema as every other surface (statusbar, titlebar,
 * panes, layouts):
 *
 *   render areas (`render`):  composer.top       — banner strip above the input
 *                             composer.bottom    — row below the input grid
 *                             composer.underside — floating strip BELOW the
 *                                                  whole composer (no chrome)
 *                             composer.leading   — inline after the "+" menu
 *                             composer.actions   — inline before the model pill
 *
 *   data kinds (`data`):      composer.middleware    (ComposerMiddleware)
 *                             composer.attachments   (ComposerAttachmentProvider)
 *                             composer.microActions  (ComposerMicroActionProvider)
 *
 * Core keeps ownership of the transcript, input, and submit engine — these
 * seams AUGMENT the composer, they never replace it. Middleware runs as an
 * ordered async chain around the app's onSubmit: each handler may rewrite the
 * draft, pass it through, cancel the send by returning null, or declare work
 * that runs only after the draft is admitted as a real new turn.
 */

import { createContext, useContext, useMemo } from 'react'

import { useContributions } from '@/contrib/react/use-contributions'
import { registry } from '@/contrib/registry'
import type { TodoItem } from '@/lib/todos'
import { cloneTurnMetadata, type TurnMetadata } from '@/lib/turn-metadata'
import type { ComposerAttachment } from '@/store/composer'
import type { ComposerAction } from '@/store/composer-actions'

export const COMPOSER_AREAS = {
  top: 'composer.top',
  bottom: 'composer.bottom',
  underside: 'composer.underside',
  leading: 'composer.leading',
  actions: 'composer.actions',
  middleware: 'composer.middleware',
  attachments: 'composer.attachments',
  microActions: 'composer.microActions'
} as const

export interface ComposerDraft {
  text: string
  attachments?: ComposerAttachment[]
  /** Namespaced, JSON-safe data bound to this one new turn. */
  turnMetadata?: TurnMetadata
}

/** Identity of the ChatBar that owns a render or submit. `storedSessionId`
 *  is the composer's durable queue key (normally the stored lineage root),
 *  while `runtimeSessionId` is the live gateway session serving that view. */
export interface ComposerContextValue {
  readonly runtimeSessionId: string | null
  readonly storedSessionId: string | null
}

const EMPTY_COMPOSER_CONTEXT: ComposerContextValue = Object.freeze({
  runtimeSessionId: null,
  storedSessionId: null
})

const ComposerContext = createContext<ComposerContextValue>(EMPTY_COMPOSER_CONTEXT)

/** Scopes render contributions to the ChatBar instance they are mounted in. */
export const ComposerContextProvider = ComposerContext.Provider

/** Read the current ChatBar's runtime + durable queue identity. */
export const useComposerContext = (): ComposerContextValue => useContext(ComposerContext)

/** Payload of a `composer.middleware` data contribution. */
export interface ComposerMiddlewareResult {
  /** The transformed draft to pass to the rest of the middleware chain. */
  draft: ComposerDraft
  /** Runs once, and only once, when this operation is admitted as a new model
   * turn. It is not called for steering, cancellation, or non-model commands. */
  onCommit?: () => void
}

export interface PreparedComposerDraft {
  draft: ComposerDraft
  /** One-shot aggregate of the middleware callbacks that requested commit. */
  commit?: () => void
}

export type ComposerMiddlewareOutput = ComposerDraft | ComposerMiddlewareResult | null

export interface ComposerMiddleware {
  /** Rewrite/pass through with a draft, cancel with null, or return
   * `{ draft, onCommit }` to defer a side effect until new-turn admission. */
  handler: (
    draft: ComposerDraft,
    context: ComposerContextValue
  ) => ComposerMiddlewareOutput | Promise<ComposerMiddlewareOutput>
}

export interface ComposerAttachmentContext {
  insertText: (text: string) => void
}

/** Payload of a `composer.attachments` data contribution — an entry in the
 *  composer's "+" attach menu. */
export interface ComposerAttachmentProvider {
  label: string
  /** Codicon name for the menu row. Defaults to `plug`. */
  icon?: string
  run: (ctx: ComposerAttachmentContext) => void | Promise<void>
}

/**
 * Run the ordered middleware chain over a draft. Contributions execute in
 * registry order (`order`, then registration order); the first `null` wins
 * and cancels the send. A throwing handler is treated as pass-through so a
 * broken plugin can't eat messages.
 */
export async function runComposerMiddleware(
  draft: ComposerDraft,
  context: ComposerContextValue = EMPTY_COMPOSER_CONTEXT
): Promise<PreparedComposerDraft | null> {
  const initialMetadata = cloneTurnMetadata(draft.turnMetadata)
  let current: ComposerDraft = initialMetadata ? { ...draft, turnMetadata: initialMetadata } : draft
  const commitCallbacks: Array<() => void> = []

  // Runtime plugins receive one immutable identity snapshot for the chain.
  // In particular, a tile/background session must never fall back to the
  // globally active ChatBar while an async middleware is running.
  const middlewareContext: ComposerContextValue = Object.freeze({
    runtimeSessionId: context.runtimeSessionId,
    storedSessionId: context.storedSessionId
  })

  for (const contribution of registry.getArea(COMPOSER_AREAS.middleware)) {
    const middleware = contribution.data as ComposerMiddleware | undefined

    if (!middleware?.handler) {
      continue
    }

    try {
      // Give each runtime contribution a detached metadata snapshot. A handler
      // that mutates its argument and then throws must still be pass-through;
      // otherwise it could smuggle an unvalidated value into the next handler.
      const middlewareDraft = {
        ...current,
        turnMetadata: cloneTurnMetadata(current.turnMetadata)
      }

      const output = await middleware.handler(middlewareDraft, middlewareContext)

      if (output === null) {
        return null
      }

      const declaredResult = !('text' in output) && 'draft' in output
      const next = declaredResult ? output.draft : output

      if (declaredResult && output.onCommit !== undefined && typeof output.onCommit !== 'function') {
        throw new TypeError('composer middleware onCommit must be a function')
      }

      // Runtime plugins are outside TypeScript's trust boundary. Validate and
      // detach their metadata at every step; an invalid result is handled by
      // the catch below exactly like a throwing middleware (pass-through).
      current = { ...next, turnMetadata: cloneTurnMetadata(next.turnMetadata) }

      if (declaredResult && output.onCommit) {
        commitCallbacks.push(output.onCommit)
      }
    } catch {
      // Pass-through: a faulty middleware must never swallow the message.
    }
  }

  if (commitCallbacks.length === 0) {
    return { draft: current }
  }

  let committed = false

  const commit = () => {
    if (committed) {
      return
    }

    committed = true

    for (const callback of commitCallbacks) {
      try {
        callback()
      } catch {
        // Admission is authoritative. A broken plugin callback cannot undo it
        // or prevent later callbacks from observing the same committed turn.
      }
    }
  }

  return { draft: current, commit }
}

/**
 * Prepare a draft at the composer boundary. Queued entries set `prepared` when
 * middleware already ran at admission; draining validates and clones that
 * snapshot without consulting today's live contribution state again.
 */
export async function prepareComposerDraft(
  draft: ComposerDraft,
  prepared = false,
  context: ComposerContextValue = EMPTY_COMPOSER_CONTEXT
): Promise<PreparedComposerDraft | null> {
  if (!prepared) {
    return runComposerMiddleware(draft, context)
  }

  return { draft: { ...draft, turnMetadata: cloneTurnMetadata(draft.turnMetadata) } }
}

/** Attach-menu entries contributed by plugins/core, with stable render keys. */
export function useComposerAttachmentProviders(): Array<ComposerAttachmentProvider & { key: string }> {
  return useContributions(COMPOSER_AREAS.attachments)
    .map(c => ({ key: `${c.source ?? 'core'}:${c.id}`, ...(c.data as ComposerAttachmentProvider) }))
    .filter(p => Boolean(p.label && p.run))
}

/**
 * Payload of a `composer.microActions` data contribution — the pill strip at
 * the top of the composer's overlay lane.
 *
 * `resolve` is called with the live session context and returns the badges to
 * show right now, or `[]` for "nothing from me". Returning a list rather than
 * a static badge is what lets a provider be conditional ("only while idle",
 * "only with unfinished tasks") without a reactive `when()`, which the
 * registry deliberately doesn't offer.
 */
export interface ComposerMicroActionProvider {
  resolve: (ctx: ComposerMicroActionContext) => ComposerAction[]
}

/** What a micro-action provider gets to branch on. Deliberately small: every
 *  field here is a standing compatibility promise to the plugins using it. */
export interface ComposerMicroActionContext {
  /** A turn is currently running in this session. */
  busy: boolean
  sessionId: string
  /** Live todo list for the session (empty when there is none). */
  todos: readonly TodoItem[]
}

/** Micro-action providers, memoised against the registry's own stable
 *  snapshot — the strip re-resolves on every composer render, so a fresh array
 *  here would defeat that. */
export function useComposerMicroActionProviders(): ComposerMicroActionProvider[] {
  const contributions = useContributions(COMPOSER_AREAS.microActions)

  return useMemo(
    () => contributions.map(c => c.data as ComposerMicroActionProvider).filter(p => typeof p?.resolve === 'function'),
    [contributions]
  )
}
