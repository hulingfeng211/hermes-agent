export type JsonPrimitive = boolean | null | number | string
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue }

/**
 * Per-turn extension data. Each top-level key is an independent namespace;
 * values must be plain, bounded JSON so they can cross JSON-RPC and be stored
 * with a queued prompt without executable objects or prototype surprises.
 */
export interface TurnMetadata {
  [namespace: string]: JsonValue
}

const MAX_BYTES = 16 * 1024
const MAX_DEPTH = 8
const MAX_NODES = 256
const MAX_CONTAINER_ENTRIES = 256
const MAX_NAMESPACES = 32
const MAX_NAMESPACE_LENGTH = 64
const MAX_OBJECT_KEY_LENGTH = 128
const NAMESPACE_RE = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

interface CloneBudget {
  nodes: number
}

const containsUnpairedSurrogate = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)

    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)

      if (next < 0xdc00 || next > 0xdfff) {
        return true
      }

      index += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true
    }
  }

  return false
}

const assertObjectKey = (key: string, label: string): void => {
  const characterLength = [...key].length

  if (
    characterLength === 0 ||
    characterLength > MAX_OBJECT_KEY_LENGTH ||
    UNSAFE_KEYS.has(key) ||
    key.startsWith('__') ||
    [...key].some(char => char.charCodeAt(0) < 0x20 || char.charCodeAt(0) === 0x7f) ||
    containsUnpairedSurrogate(key)
  ) {
    throw new TypeError(`${label} contains an invalid object key`)
  }
}

const assertPlainObject = (value: object, label: string): void => {
  const prototype = Object.getPrototypeOf(value)

  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must contain only plain JSON objects`)
  }

  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      throw new TypeError(`${label} must not contain symbol keys`)
    }

    const descriptor = Object.getOwnPropertyDescriptor(value, key)

    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError(`${label} must contain only enumerable data properties`)
    }
  }
}

const accountNode = (budget: CloneBudget): void => {
  budget.nodes += 1

  if (budget.nodes > MAX_NODES) {
    throw new RangeError(`turn metadata exceeds ${MAX_NODES} JSON values`)
  }
}

const cloneJsonValue = (value: unknown, depth: number, budget: CloneBudget, seen: WeakSet<object>): JsonValue => {
  if (depth > MAX_DEPTH) {
    throw new RangeError(`turn metadata exceeds maximum depth ${MAX_DEPTH}`)
  }

  accountNode(budget)

  if (value === null || typeof value === 'boolean') {
    return value
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('turn metadata numbers must be finite')
    }

    return value
  }

  if (typeof value === 'string') {
    if (containsUnpairedSurrogate(value)) {
      throw new TypeError('turn metadata strings must be valid Unicode')
    }

    return value
  }

  if (typeof value !== 'object') {
    throw new TypeError('turn metadata must contain only JSON values')
  }

  if (seen.has(value)) {
    throw new TypeError('turn metadata must not contain cycles')
  }

  seen.add(value)

  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw new TypeError('turn metadata must contain only plain JSON arrays')
      }

      if (value.length > MAX_CONTAINER_ENTRIES) {
        throw new RangeError(`turn metadata arrays must not exceed ${MAX_CONTAINER_ENTRIES} entries`)
      }

      const ownKeys = Reflect.ownKeys(value)

      if (
        ownKeys.some(key => {
          if (key === 'length') {
            return false
          }

          if (typeof key !== 'string') {
            return true
          }

          const index = Number(key)

          return !Number.isInteger(index) || index < 0 || index >= value.length || String(index) !== key
        })
      ) {
        throw new TypeError('turn metadata arrays must not contain custom properties')
      }

      const clone: JsonValue[] = []

      for (let index = 0; index < value.length; index += 1) {
        if (!Object.prototype.hasOwnProperty.call(value, index)) {
          throw new TypeError('turn metadata arrays must not contain holes')
        }

        const descriptor = Object.getOwnPropertyDescriptor(value, String(index))

        if (!descriptor?.enumerable || !('value' in descriptor)) {
          throw new TypeError('turn metadata arrays must contain only data properties')
        }

        clone.push(cloneJsonValue(descriptor.value, depth + 1, budget, seen))
      }

      return clone
    }

    assertPlainObject(value, 'turn metadata')
    const entries = Object.entries(value)

    if (entries.length > MAX_CONTAINER_ENTRIES) {
      throw new RangeError(`turn metadata objects must not exceed ${MAX_CONTAINER_ENTRIES} entries`)
    }

    const clone: Record<string, JsonValue> = {}

    for (const [key, entry] of entries) {
      assertObjectKey(key, 'turn metadata')

      clone[key] = cloneJsonValue(entry, depth + 1, budget, seen)
    }

    return clone
  } finally {
    seen.delete(value)
  }
}

/** Validate and detach a metadata map before it crosses an async/storage/RPC boundary. */
export function cloneTurnMetadata(value: unknown): TurnMetadata | undefined {
  if (value === undefined) {
    return undefined
  }

  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('turn metadata must be a namespace map')
  }

  assertPlainObject(value, 'turn metadata')
  const entries = Object.entries(value)

  if (entries.length === 0) {
    return undefined
  }

  if (entries.length > MAX_NAMESPACES) {
    throw new RangeError(`turn metadata must not exceed ${MAX_NAMESPACES} namespaces`)
  }

  const clone: TurnMetadata = {}
  const budget: CloneBudget = { nodes: 0 }
  const seen = new WeakSet<object>([value])

  for (const [namespace, entry] of entries) {
    if (
      namespace.length === 0 ||
      namespace.length > MAX_NAMESPACE_LENGTH ||
      !NAMESPACE_RE.test(namespace) ||
      UNSAFE_KEYS.has(namespace)
    ) {
      throw new TypeError(`invalid turn metadata namespace: ${namespace || '(empty)'}`)
    }

    clone[namespace] = cloneJsonValue(entry, 1, budget, seen)
  }

  const encoded = new TextEncoder().encode(JSON.stringify(clone))

  if (encoded.byteLength > MAX_BYTES) {
    throw new RangeError(`turn metadata must not exceed ${MAX_BYTES} UTF-8 bytes`)
  }

  return clone
}
