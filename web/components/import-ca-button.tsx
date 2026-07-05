"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { importIssuer, type Issuer } from "@/lib/api";

// ImportCAButton implements mode B (CA import). It is shown only for CA issuers
// not yet in Vault, and requires an explicit consent step naming the target PKI
// mount, since it performs a WRITE to Vault.
export default function ImportCAButton({ issuer }: { issuer: Issuer }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [mount, setMount] = useState("pki");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  if (!issuer.is_ca) {
    return null;
  }
  if (issuer.vault_pki_mount) {
    return <span className="badge badge-success">In Vault</span>;
  }

  async function confirm() {
    setBusy(true);
    setMessage("");
    try {
      await importIssuer(issuer.id, mount.trim() || "pki");
      setOpen(false);
      router.refresh();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Import failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button type="button" className="button button-secondary" onClick={() => setOpen(true)}>
        Import CA to Vault
      </button>
      {open && (
        <div className="modal-overlay" role="dialog" aria-modal="true">
          <div className="modal">
            <h3 style={{ marginTop: 0 }}>Import CA to Vault</h3>
            <p className="help-text">
              This <strong>writes</strong> the CA bundle for{" "}
              <code>{issuer.subject_cn || issuer.fingerprint_sha256.slice(0, 12)}</code> into the
              Vault PKI mount below via <code>pki/issuers/import/bundle</code>. Requires a
              read-write PKI policy on the configured Vault token.
            </p>
            <div className="form-field" style={{ marginBottom: 12 }}>
              <label htmlFor="mount">PKI mount</label>
              <input id="mount" value={mount} onChange={(e) => setMount(e.target.value)} />
            </div>
            {message && <p className="help-text">{message}</p>}
            <div className="table-actions">
              <button
                type="button"
                className="button button-primary"
                onClick={() => void confirm()}
                disabled={busy}
              >
                {busy ? "Importing…" : "Confirm import"}
              </button>
              <button
                type="button"
                className="button button-secondary"
                onClick={() => setOpen(false)}
                disabled={busy}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
