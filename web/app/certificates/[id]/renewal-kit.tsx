"use client";

import { useState } from "react";
import { getRenewalKit, type Certificate, type RenewalArtifact } from "@/lib/api";

// RenewalKit implements the Mode C helper: generate vault-agent HCL or an AAP
// playbook to reissue+deploy this cert from a chosen Vault PKI role. CLM does not
// deploy — the operator runs the artifact, and a later rescan+reconcile verifies.
export default function RenewalKit({ cert }: { cert: Certificate }) {
  const [target, setTarget] = useState("agent");
  const [role, setRole] = useState("");
  const [mount, setMount] = useState("pki");
  const [service, setService] = useState("");
  const [busy, setBusy] = useState(false);
  const [artifacts, setArtifacts] = useState<RenewalArtifact[]>([]);
  const [message, setMessage] = useState("");

  async function generate() {
    if (!role.trim()) {
      setMessage("Enter a Vault PKI role");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      const res = await getRenewalKit(cert.id, { target, role: role.trim(), mount: mount.trim(), service: service.trim() });
      setArtifacts(res.artifacts);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Generation failed");
      setArtifacts([]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Renewal kit (Mode C)</h2>
      </div>
      <div className="panel-body">
        <p className="help-text">
          Generate reissue+deploy artifacts for a Vault PKI role. CLM does not deploy —
          run the artifact with Vault Agent / AAP, then rescan to verify via reconcile.
        </p>
        <div className="form-row">
          <div className="form-field">
            <label htmlFor="rk-target">Target</label>
            <select id="rk-target" value={target} onChange={(e) => setTarget(e.target.value)}>
              <option value="agent">Vault Agent</option>
              <option value="aap">Ansible (AAP)</option>
            </select>
          </div>
          <div className="form-field">
            <label htmlFor="rk-mount">PKI mount</label>
            <input id="rk-mount" value={mount} onChange={(e) => setMount(e.target.value)} />
          </div>
          <div className="form-field">
            <label htmlFor="rk-role">PKI role</label>
            <input id="rk-role" value={role} onChange={(e) => setRole(e.target.value)} placeholder="web-server" />
          </div>
          <div className="form-field">
            <label htmlFor="rk-service">Service to reload (optional)</label>
            <input id="rk-service" value={service} onChange={(e) => setService(e.target.value)} placeholder="nginx" />
          </div>
        </div>
        <div className="table-actions" style={{ marginTop: 12 }}>
          <button type="button" className="button button-primary" onClick={() => void generate()} disabled={busy}>
            {busy ? "Generating…" : "Generate kit"}
          </button>
        </div>
        {message && <p className="help-text">{message}</p>}
        {artifacts.map((a) => (
          <div key={a.filename} style={{ marginTop: 16 }}>
            <strong>{a.filename}</strong>
            <pre className="code-block">{a.content}</pre>
          </div>
        ))}
      </div>
    </section>
  );
}
