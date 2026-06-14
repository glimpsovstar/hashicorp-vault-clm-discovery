"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createScan } from "@/lib/api";

export default function ScanForm() {
  const router = useRouter();
  const [cidrs, setCidrs] = useState("127.0.0.1/32");
  const [ports, setPorts] = useState("443");
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!consent) {
      setError("You must confirm authorized scanning");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await createScan({
        cidrs: cidrs.split(",").map((c) => c.trim()).filter(Boolean),
        ports: ports.split(",").map((p) => parseInt(p.trim(), 10)).filter((n) => !Number.isNaN(n)),
        consent: true,
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <div className="form-row">
        <label>
          CIDR ranges (comma-separated)
          <input value={cidrs} onChange={(e) => setCidrs(e.target.value)} style={{ minWidth: 280 }} />
        </label>
        <label>
          Ports
          <input value={ports} onChange={(e) => setPorts(e.target.value)} />
        </label>
      </div>
      <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12 }}>
        <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
        I confirm I am authorized to scan these network targets
      </label>
      <button type="submit" disabled={loading}>{loading ? "Starting..." : "Start scan"}</button>
      {error && <p style={{ color: "#f87171" }}>{error}</p>}
      <p className="muted">Private ranges require ALLOW_PRIVATE_RANGES=true on the API server.</p>
    </form>
  );
}
