"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Certificate } from "@/lib/api";
import { catalogImport } from "@/lib/api";

// CatalogImportButton implements mode A (catalog): mark the certificate tracked
// in CLM (managed_status=imported). It is a no-op for certs already managed in
// Vault (the API returns 409), so the button is hidden in that case.
export default function CatalogImportButton({ cert }: { cert: Certificate }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  if (cert.managed_status === "managed_in_vault") {
    return null;
  }

  const alreadyImported = cert.managed_status === "imported";

  async function onClick() {
    setBusy(true);
    setMessage("");
    try {
      await catalogImport(cert.id);
      setMessage("Tracked in CLM");
      router.refresh();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Catalog import failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <button
        type="button"
        className="button button-secondary"
        onClick={() => void onClick()}
        disabled={busy || alreadyImported}
      >
        {alreadyImported ? "Tracked in CLM" : busy ? "Tracking…" : "Track in CLM"}
      </button>
      {message && <p className="help-text">{message}</p>}
    </div>
  );
}
