import type { ReconcileSummary } from "@/lib/api";

/**
 * reconcileStatusMessage maps a reconcile result to a user-facing message.
 *
 * A fully failed reconcile (nothing could be read from Vault) must never be
 * presented as success — it returns a distinct failure message. A partial run
 * appends an error count to the caller's success text. `successBase` is supplied
 * by the caller because each surface phrases the success line differently.
 */
export function reconcileStatusMessage(
  result: ReconcileSummary,
  successBase: string
): string {
  if (result.status === "failed") {
    return `Reconcile failed: could not read any certificates from ${result.mounts_scanned} PKI mount(s). ${
      result.errors[0] ?? ""
    }`.trim();
  }
  if (result.status === "partial") {
    return `${successBase} — ${result.errors.length} error(s), some certificates could not be read`;
  }
  return successBase;
}
