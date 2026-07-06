"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { checkRevocation, type Certificate, type RevocationResult } from "@/lib/api";

// RevocationCheckButton runs an on-demand CRL revocation check (mode: shadow
// certs). The result is advisory unless the CRL signature was verified against a
// known issuer, in which case the server persists status=revoked.
export default function RevocationCheckButton({ cert }: { cert: Certificate }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<RevocationResult | null>(null);
  const [message, setMessage] = useState("");

  async function onClick() {
    setBusy(true);
    setMessage("");
    try {
      const r = await checkRevocation(cert.id);
      setResult(r);
      if (r.status === "revoked" && r.verified) {
        router.refresh();
      }
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Revocation check failed");
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
        disabled={busy}
      >
        {busy ? "Checking…" : "Check revocation"}
      </button>
      {result && (
        <p className="help-text">
          Status: <strong>{result.status}</strong>
          {result.source ? ` (${result.source})` : ""} —{" "}
          {result.verified ? "signature verified" : "unverified (advisory)"}
        </p>
      )}
      {message && <p className="help-text">{message}</p>}
    </div>
  );
}
