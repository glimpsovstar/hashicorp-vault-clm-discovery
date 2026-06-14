"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createScan } from "@/lib/api";

export default function ScanForm() {
  const router = useRouter();
  const [cidrs, setCidrs] = useState("");
  const [hostnames, setHostnames] = useState(
    "aap.david-joo.sbx.hashidemos.io,coffeesnob.withdevo.net"
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
        <div className="form-field form-field-wide">
          <label htmlFor="hostnames">Hostnames (comma-separated)</label>
          <input
            id="hostnames"
            value={hostnames}
            onChange={(e) => setHostnames(e.target.value)}
            placeholder="app.example.com,api.example.com"
          />
        </div>
        <div className="form-field">
          <label htmlFor="cidrs">CIDR ranges (optional)</label>
          <input
            id="cidrs"
            value={cidrs}
            onChange={(e) => setCidrs(e.target.value)}
            placeholder="1.1.1.1/32"
          />
        </div>
        <div className="form-field">
          <label htmlFor="ports">Ports</label>
          <input id="ports" value={ports} onChange={(e) => setPorts(e.target.value)} />
        </div>
      </div>

      <label className="checkbox-row">
        <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
        I confirm I am authorized to scan these network targets
      </label>

      <button type="submit" className="button button-primary" disabled={loading}>
        {loading ? "Starting..." : "Start scan"}
      </button>

      {error && <p className="error-text">{error}</p>}

      <p className="help-text">
        Use hostnames for HTTPS sites (correct SNI). CIDR scans use the IP as SNI — fine for
        dedicated IPs, wrong for shared hosting. Unresolvable hostnames are skipped with a warning;
        the scan still runs for names that resolve.
      </p>
    </form>
  );
}
