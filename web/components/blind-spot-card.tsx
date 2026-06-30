"use client";

import { useCallback, useEffect, useState } from "react";
import {
  downloadReport,
  fetchBlindSpot,
  triggerReconcile,
  type BlindSpotSummary,
} from "@/lib/api";

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
  const [downloading, setDownloading] = useState(false);
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
      setMessage(`Reconcile complete: ${result.matched} matched, ${result.unmatched_clm} unmatched in CLM`);
      await loadSummary();
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

  async function handleDownload() {
    setDownloading(true);
    setMessage(null);
    try {
      await downloadReport(scanId, "markdown");
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Download failed");
    } finally {
      setDownloading(false);
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
            <StatTile label="On wire" value={summary?.discovered ?? "—"} />
            <StatTile label="Shadow certs" value={summary?.shadow ?? "—"} />
            <StatTile label="SC-081 violations" value={summary?.sc081_violations ?? "—"} />
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
              {reconciling ? "Reconciling…" : "Reconcile with Vault"}
            </button>
          )}
          <button
            type="button"
            className="button button-secondary"
            onClick={() => void handleDownload()}
            disabled={downloading}
          >
            {downloading ? "Downloading…" : "Download report"}
          </button>
        </div>

        {message && <p className="help-text">{message}</p>}
      </div>
    </section>
  );
}

function StatTile({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="stat-tile">
      <div className="stat-tile-label">{label}</div>
      <div className="stat-tile-value">{value}</div>
    </div>
  );
}
