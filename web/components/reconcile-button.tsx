"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { triggerReconcile, type ReconcileSummary } from "@/lib/api";

function reconcileMessage(result: ReconcileSummary): string {
  if (result.status === "failed") {
    return `Reconcile failed: could not read any certificates from ${result.mounts_scanned} PKI mount(s). ${result.errors[0] ?? ""}`.trim();
  }
  const base = `Reconcile complete: ${result.matched} matched across ${result.mounts_scanned} PKI mount(s)`;
  if (result.status === "partial") {
    return `${base} — ${result.errors.length} error(s), some certificates could not be read`;
  }
  return base;
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
