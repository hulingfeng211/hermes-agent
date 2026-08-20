/**
 * One-shot authority for a submit that entered through the external composer
 * bus. The token stays cancellable while plugin middleware and the native
 * submit pipeline are preparing the turn. `commit()` closes that window at
 * the actual gateway-send boundary; after that, the caller follows the real
 * submit result instead of reporting a cancellation for work already sent.
 */
export interface ComposerSubmitAdmission {
  readonly signal: AbortSignal
  /** Move from middleware admission into native submit preparation. */
  beginSubmit(): boolean
  /** True while the target/backend snapshot is still authoritative. */
  isValid(): boolean
  /** Atomically validate and claim the gateway-send boundary. */
  commit(): boolean
}

export type ComposerSubmitAdmissionPhase = 'admission' | 'submitting'
