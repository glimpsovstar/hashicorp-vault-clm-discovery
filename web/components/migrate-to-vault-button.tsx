"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { migrateToVault, type Certificate } from "@/lib/api";
import LifecycleJobPending from "@/components/lifecycle-job-pending";

const CONSENT_COPY =
  "Vault will issue a new certificate via AAP. CLM cannot upload the scanned certificate — there is no private key. The old leaf is replaced. Status stays Pending until the new fingerprint is on the wire or the job times out (default 24 hours).";

export default function MigrateToVaultButton({
  cert,
  compact = false,
}: {
  cert: Certificate;
  compact?: boolean;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [mount, setMount] = useState("pki");
  const [role, setRole] = useState("");
  const [service, setService] = useState("");
  const [targetHosts, setTargetHosts] = useState("");

  if (cert.managed_status === "managed_in_vault" || cert.is_ca) {
    return null;
  }

  async function onConfirm() {
    if (!role.trim()) {
      setMessage("Enter a Vault PKI role");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      const res = await migrateToVault(cert.id, {
        consent: true,
        mount: mount.trim() || "pki",
        role: role.trim(),
        service: service.trim() || undefined,
        target_hosts: targetHosts.trim() || undefined,
      });
      setJobId(res.lifecycle_job_id);
      setOpen(false);
      router.refresh();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Migrate failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <button
        type="button"
        className={compact ? "button button-secondary" : "button button-primary"}
        onClick={() => setOpen(true)}
        disabled={busy}
      >
        Migrate to Vault
      </button>
      {open && (
        <div className="panel" style={{ marginTop: 12 }} role="dialog" aria-label="Migrate to Vault consent">
          <div className="panel-body">
            <p className="help-text">{CONSENT_COPY}</p>
            <div className="form-row">
              <div className="form-field">
                <label htmlFor={`mig-mount-${cert.id}`}>PKI mount</label>
                <input
                  id={`mig-mount-${cert.id}`}
                  value={mount}
                  onChange={(e) => setMount(e.target.value)}
                />
              </div>
              <div className="form-field">
                <label htmlFor={`mig-role-${cert.id}`}>PKI role</label>
                <input
                  id={`mig-role-${cert.id}`}
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  placeholder="web-server"
                />
              </div>
              <div className="form-field">
                <label htmlFor={`mig-service-${cert.id}`}>Service (optional)</label>
                <input
                  id={`mig-service-${cert.id}`}
                  value={service}
                  onChange={(e) => setService(e.target.value)}
                  placeholder="nginx"
                />
              </div>
              <div className="form-field">
                <label htmlFor={`mig-hosts-${cert.id}`}>Target hosts (optional)</label>
                <input
                  id={`mig-hosts-${cert.id}`}
                  value={targetHosts}
                  onChange={(e) => setTargetHosts(e.target.value)}
                />
              </div>
            </div>
            <div className="table-actions" style={{ marginTop: 12, display: "flex", gap: 8 }}>
              <button
                type="button"
                className="button button-primary"
                onClick={() => void onConfirm()}
                disabled={busy}
              >
                {busy ? "Launching…" : "Confirm migrate"}
              </button>
              <button type="button" className="button button-secondary" onClick={() => setOpen(false)} disabled={busy}>
                Cancel
              </button>
            </div>
            {message && <p className="help-text">{message}</p>}
          </div>
        </div>
      )}
      {jobId && <LifecycleJobPending jobId={jobId} />}
    </div>
  );
}
