"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  fetchBlindSpot,
  triggerReconcile,
  type BlindSpotSummary,
  type ReconcileSummary,
} from "@/lib/api";
import { reconcileStatusMessage } from "@/lib/reconcile";
import HelpPopover from "@/components/help-popover";

function reconcileMessage(result: ReconcileSummary): string {
  return reconcileStatusMessage(
    result,
    `Reconcile complete: ${result.matched} matched, ${result.unmatched_clm} unmatched in CLM`
  );
}

const README_VAULT_URL =
  "https://github.com/glimpsovstar/hashicorp-vault-clm-discovery#environment-variables";

type Props = {
  scanId: string;
  scanStatus: string;
};

export default function BlindSpotCard({ scanId, scanStatus }: Props) {
  const [summary, setSummary] = useState<BlindSpotSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [vaultConfigured, setVaultConfigured] = useState(true);

  const loadSummary = useCallback(async () => {
    if (scanStatus !== "completed") {
      return;
    }
    setLoading(true);
    try {
      const data = await fetchBlindSpot(scanId);
      setSummary(data);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Failed to load blind-spot summary");
    } finally {
      setLoading(false);
    }
  }, [scanId, scanStatus]);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  async function handleReconcile() {
    setReconciling(true);
    setMessage(null);
    try {
      const result = await triggerReconcile();
      setVaultConfigured(true);
      setMessage(reconcileMessage(result));
      // A fully failed reconcile changed nothing, so skip the metrics refresh.
      if (result.status !== "failed") {
        // Refresh the metrics, but keep the reconcile message even if the
        // follow-up read fails — the reconcile itself ran.
        try {
          const data = await fetchBlindSpot(scanId);
          setSummary(data);
        } catch {
          // best-effort refresh; leave the message in place
        }
      }
    } catch (err) {
      const text = err instanceof Error ? err.message : "Reconcile failed";
      if (text.toLowerCase().includes("vault not configured")) {
        setVaultConfigured(false);
        setMessage(null);
      } else {
        setMessage(text);
      }
    } finally {
      setReconciling(false);
    }
  }

  if (scanStatus !== "completed") {
    return (
      <section className="panel">
        <div className="panel-header">
          <h2>Blind-spot reveal</h2>
        </div>
        <div className="panel-body">
          <p className="muted">Complete the scan to view Vault blind-spot metrics and download a report.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Blind-spot reveal</h2>
      </div>
      <div className="panel-body">
        {loading && !summary && <p className="muted">Loading metrics…</p>}

        {!vaultConfigured ? (
          <>
            <div className="stat-grid stat-grid-single">
              <StatTile label="On wire (scan)" value={summary?.discovered ?? "—"} />
            </div>
            <p className="help-text">
              Vault is not configured. Set <code>VAULT_ADDR</code> and <code>VAULT_TOKEN</code> to
              enable reconcile and full blind-spot metrics.{" "}
              <a href={README_VAULT_URL} target="_blank" rel="noopener noreferrer">
                README setup
              </a>
            </p>
          </>
        ) : (
          <div className="stat-grid">
            <StatTile label="Vault managed" value={summary?.vault_managed ?? "—"} />
            <StatTile
              label="On wire"
              value={summary?.discovered ?? "—"}
              help={
                <>
                  Certificates observed live during this scan — every TLS endpoint
                  that presented a certificate on the wire.
                </>
              }
            />
            <StatTile
              label="Shadow certs"
              value={summary?.shadow ?? "—"}
              help={
                <>
                  On the wire but <strong>not issued by Vault</strong> — deployed yet
                  unmanaged. These are your blind spots. Run <em>Show shadow certs</em>{" "}
                  to refresh this count.
                </>
              }
            />
            <StatTile
              label="SC-081 violations"
              value={summary?.sc081_violations ?? "—"}
              help={
                <>
                  Certificates that breach the <strong>SC-081</strong> compliance rules
                  — expiry thresholds and excessive issued validity. Each is a finding
                  that needs remediation.
                </>
              }
            />
          </div>
        )}

        <div className="table-actions" style={{ marginTop: 16 }}>
          {vaultConfigured && (
            <button
              type="button"
              className="button button-primary"
              onClick={() => void handleReconcile()}
              disabled={reconciling}
            >
              {reconciling ? "Checking…" : "Show shadow certs"}
            </button>
          )}
          <Link className="button button-secondary" href={`/scans/${scanId}/report`}>
            View report
          </Link>
        </div>

        {message && <p className="help-text">{message}</p>}
      </div>
    </section>
  );
}

function StatTile({
  label,
  value,
  help,
}: {
  label: string;
  value: number | string;
  help?: ReactNode;
}) {
  return (
    <div className="stat-tile">
      <div className="stat-tile-label">
        {label}
        {help && <HelpPopover label={`What is “${label}”?`}>{help}</HelpPopover>}
      </div>
      <div className="stat-tile-value">{value}</div>
    </div>
  );
}
