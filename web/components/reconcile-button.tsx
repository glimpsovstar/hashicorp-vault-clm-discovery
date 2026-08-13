"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { triggerReconcile, type ReconcileSummary } from "@/lib/api";
import { reconcileStatusMessage } from "@/lib/reconcile";

function reconcileMessage(result: ReconcileSummary): string {
  return reconcileStatusMessage(
    result,
    `Reconcile complete: ${result.matched} matched across ${result.mounts_scanned} PKI mount(s)`
  );
}

export default function ReconcileButton() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [vaultMissing, setVaultMissing] = useState(false);

  async function handleClick() {
    setLoading(true);
    setMessage(null);
    setVaultMissing(false);
    try {
      const result = await triggerReconcile();
      setMessage(reconcileMessage(result));
      router.refresh();
    } catch (err) {
      const text = err instanceof Error ? err.message : "Reconcile failed";
      if (text.toLowerCase().includes("vault not configured")) {
        setVaultMissing(true);
      } else {
        setMessage(text);
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="reconcile-toolbar">
      <button
        type="button"
        className="button button-primary"
        onClick={() => void handleClick()}
        disabled={loading}
      >
        {loading ? "Reconciling…" : "Reconcile with Vault"}
      </button>
      {vaultMissing && (
        <p className="help-text">
          Vault is not configured.{" "}
          <Link href="/settings/connections">Open Settings</Link> to add a connection, or set{" "}
          <code>VAULT_ADDR</code> and <code>VAULT_TOKEN</code> in the environment.
        </p>
      )}
      {message && <p className="help-text">{message}</p>}
    </div>
  );
}
