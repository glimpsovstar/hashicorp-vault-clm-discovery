"use client";

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

const README_VAULT_URL =
  "https://github.com/glimpsovstar/hashicorp-vault-clm-discovery#environment-variables";

export default function ReconcileButton() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function handleClick() {
    setLoading(true);
    setMessage(null);
    try {
      const result = await triggerReconcile();
      setMessage(reconcileMessage(result));
      router.refresh();
    } catch (err) {
      const text = err instanceof Error ? err.message : "Reconcile failed";
      if (text.toLowerCase().includes("vault not configured")) {
        setMessage(
          `Vault not configured — set VAULT_ADDR and VAULT_TOKEN. See README: ${README_VAULT_URL}`
        );
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
      {message && <p className="help-text">{message}</p>}
    </div>
  );
}
