"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createScan } from "@/lib/api";

export default function ScanForm() {
  const router = useRouter();
  const [cidrs, setCidrs] = useState("");
  const [hostnames, setHostnames] = useState(
    "aap.david-joo.sbx.hashicorp.io,coffeesnob.withdevo.net"
  );
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
    const cidrList = cidrs.split(",").map((c) => c.trim()).filter(Boolean);
    const hostnameList = hostnames.split(",").map((h) => h.trim()).filter(Boolean);
    if (cidrList.length === 0 && hostnameList.length === 0) {
      setError("Provide at least one CIDR or hostname");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await createScan({
        cidrs: cidrList,
        hostnames: hostnameList,
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
          Hostnames (comma-separated)
          <input
            value={hostnames}
            onChange={(e) => setHostnames(e.target.value)}
            placeholder="app.example.com,api.example.com"
            style={{ minWidth: 320 }}
          />
        </label>
        <label>
          CIDR ranges (optional)
          <input value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="1.1.1.1/32" />
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
      <p className="muted">
        Use hostnames for HTTPS sites (correct SNI). CIDR scans use the IP as SNI — fine for dedicated IPs, wrong for shared hosting.
      </p>
    </form>
  );
}
