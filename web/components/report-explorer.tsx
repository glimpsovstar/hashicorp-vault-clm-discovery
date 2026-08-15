"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import {
  severityCounts,
  findingSeverityBadgeClass,
  type Finding,
  type FindingSeverity,
} from "@/lib/findings";
import CatalogImportButton from "@/components/catalog-import-button";
import MigrateToVaultButton from "@/components/migrate-to-vault-button";
import ImportCAButton from "@/components/import-ca-button";

const SEVERITY_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};
const KIND_TABS = [
  { id: "all", label: "All" },
  { id: "persisted", label: "Findings" },
  { id: "shadow", label: "Shadow certs" },
  { id: "insight", label: "Insights" },
  { id: "issuer", label: "CA issuers" },
] as const;

type Coverage = { managed: number; shadow: number; discovered: number; pct: number };

export default function ReportExplorer({
  findings,
  coverage,
}: {
  findings: Finding[];
  coverage: Coverage;
}) {
  const [severities, setSeverities] = useState<Set<FindingSeverity>>(new Set());
  const [kind, setKind] = useState<string>("all");
  const [query, setQuery] = useState("");

  const counts = useMemo(() => severityCounts(findings), [findings]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (severities.size && !severities.has(f.severity)) return false;
      if (kind !== "all" && f.kind !== kind) return false;
      if (q && !`${f.subject} ${f.secondary}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [findings, severities, kind, query]);

  function toggleSeverity(sev: FindingSeverity) {
    setSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  }

  return (
    <div className="report-explorer">
      {/* Severity overview */}
      <div className="sev-overview">
        {SEVERITY_ORDER.map((sev) => (
          <button
            key={sev}
            type="button"
            className={`sev-card sev-${sev}${severities.has(sev) ? " active" : ""}`}
            onClick={() => toggleSeverity(sev)}
            aria-pressed={severities.has(sev)}
          >
            <span className="sev-card-n">{counts[sev]}</span>
            <span className="sev-card-lbl">{SEVERITY_LABEL[sev]}</span>
          </button>
        ))}
        <div className="coverage-card">
          <div className="coverage-top">
            <span className="coverage-pct">{coverage.pct}%</span>
            <span className="coverage-cap">Vault coverage</span>
          </div>
          <div className="coverage-meter">
            <span style={{ width: `${coverage.pct}%` }} />
          </div>
          <div className="coverage-sub">
            <b>{coverage.managed}</b> managed · <b>{coverage.shadow}</b> shadow of{" "}
            <b>{coverage.discovered}</b> on the wire
          </div>
        </div>
      </div>

      {/* Findings panel */}
      <section className="panel">
        <div className="explorer-toolbar">
          <h2>
            Findings <span className="muted">({visible.length})</span>
          </h2>
          <div className="explorer-toolbar-spacer" />
          <input
            type="search"
            className="explorer-search"
            placeholder="Search subject or serial…"
            aria-label="Search findings"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="chip-row">
            {SEVERITY_ORDER.map((sev) => (
              <button
                key={sev}
                type="button"
                className={`filter-chip chip-${sev}${severities.has(sev) ? " on" : ""}`}
                onClick={() => toggleSeverity(sev)}
                aria-pressed={severities.has(sev)}
              >
                {SEVERITY_LABEL[sev]}
              </button>
            ))}
          </div>
          <div className="kind-seg">
            {KIND_TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                className={kind === t.id ? "on" : ""}
                onClick={() => setKind(t.id)}
                aria-pressed={kind === t.id}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div className="data-table-wrap">
          {visible.length === 0 ? (
            <p className="muted" style={{ padding: "24px 20px", textAlign: "center" }}>
              {findings.length === 0
                ? "No findings — every discovered certificate is healthy and accounted for."
                : "No findings match the current filters."}
            </p>
          ) : (
            <table className="data-table findings-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Subject</th>
                  <th>Vault status</th>
                  <th>Days left</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {visible.map((f) => (
                  <FindingRow key={f.key} f={f} />
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}

function daysClass(days: number | null): string {
  if (days === null) return "";
  if (days < 0) return "days-neg";
  if (days <= 30) return "days-warn";
  return "";
}
function daysText(days: number | null): string {
  if (days === null) return "—";
  return days < 0 ? `${Math.abs(days)}d ago` : `${days}d`;
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr
        className={`finding-row sev-row-${f.severity}${open ? " open" : ""}`}
        onClick={() => setOpen((v) => !v)}
        tabIndex={0}
        aria-expanded={open}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
      >
        <td className="sev-cell">
          <span className={findingSeverityBadgeClass(f.severity)}>{f.severity}</span>
        </td>
        <td>{f.typeLabel}</td>
        <td>
          <span className="finding-subject">{f.subject}</span>
          <span className="finding-secondary">{f.secondary}</span>
        </td>
        <td>
          {f.vault === "shadow" ? (
            <span className="vault-pip vault-shadow">Shadow</span>
          ) : f.vault === "managed" ? (
            <span className="vault-pip vault-managed">Managed</span>
          ) : f.vault === "tracked" ? (
            <span className="vault-pip vault-tracked">Tracked</span>
          ) : (
            <span className="muted">—</span>
          )}
        </td>
        <td className={`tnum ${daysClass(f.days)}`}>{daysText(f.days)}</td>
        <td>
          <span className="row-caret" aria-hidden>{open ? "▾" : "▸"}</span>
        </td>
      </tr>
      {open && (
        <tr className="finding-detail">
          <td colSpan={6}>
            <div className="finding-detail-inner">
              {f.description && <p className="finding-detail-desc">{f.description}</p>}
              <div className="finding-detail-grid">
                {f.issuerDn && <Kv k="Issuer" v={f.issuerDn} />}
                {f.serial && <Kv k="Serial" v={f.serial} mono />}
                {f.fingerprint && <Kv k="Fingerprint (SHA-256)" v={f.fingerprint} mono />}
                {f.cert && <Kv k="Last seen" v={new Date(f.cert.last_seen).toLocaleString()} />}
                {f.cert && <Kv k="Scope" v={f.cert.cert_scope} />}
              </div>
              <div className="finding-detail-actions">
                {f.cert && <CatalogImportButton cert={f.cert} />}
                {f.cert && <MigrateToVaultButton cert={f.cert} compact />}
                {f.issuer && <ImportCAButton issuer={f.issuer} />}
                {f.cert && (
                  <Link className="button button-secondary" href={`/certificates/${f.cert.id}`}>
                    View certificate
                  </Link>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function Kv({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="kv">
      <div className="kv-k">{k}</div>
      <div className={`kv-v${mono ? " mono" : ""}`}>{v}</div>
    </div>
  );
}
