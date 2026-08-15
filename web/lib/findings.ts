import type { Certificate, Issuer, ReportInsight, BlindSpotSummary, ReportDocument, PersistedFinding } from "@/lib/api";
import { selectShadowCerts, selectScanIssuers } from "@/lib/report";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingKind = "insight" | "shadow" | "issuer" | "persisted";

export type Finding = {
  key: string;
  kind: FindingKind;
  severity: FindingSeverity;
  typeLabel: string;
  subject: string;
  secondary: string;
  vault: "shadow" | "managed" | "tracked" | "na";
  days: number | null;
  description?: string;
  issuerDn?: string;
  fingerprint?: string;
  serial?: string;
  waived?: boolean;
  cert?: Certificate;
  issuer?: Issuer;
};

// Shadow certs are unmanaged by definition; severity escalates with expiry proximity.
// NOTE: thresholds are hard-coded for v1 — see #73 follow-up to make them configurable.
export function deriveShadowSeverity(cert: Certificate): FindingSeverity {
  if (cert.status === "expired" || cert.days_until_expiry < 0) return "critical";
  if (cert.days_until_expiry <= 7) return "critical";
  if (cert.days_until_expiry <= 30) return "high";
  return "medium";
}

// CA-import opportunities are lower urgency unless the CA itself is expiring.
export function deriveIssuerSeverity(issuer: Issuer): FindingSeverity {
  return issuer.days_until_expiry <= 30 ? "high" : "low";
}

const SEVERITY_WORDS = new Set(["critical", "high", "medium", "low", "warning", "info"]);

function humanizeInsightType(type: string): string {
  const parts = type.split(".");
  if (parts.length > 1 && SEVERITY_WORDS.has(parts[parts.length - 1])) parts.pop();
  const words = parts
    .map((p) => (p === "sc081" ? "SC-081" : p.replace(/[_-]/g, " ")))
    .join(" ")
    .trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function insightToFinding(insight: ReportInsight, i: number): Finding {
  return {
    key: `insight-${insight.fingerprint_sha256 ?? insight.type}-${i}`,
    kind: "insight",
    severity: insight.severity,
    typeLabel: humanizeInsightType(insight.type),
    subject: insight.subject_cn || insight.issuer_dn || "—",
    secondary: insight.category,
    vault: "na",
    days: null,
    description: insight.description,
    issuerDn: insight.issuer_dn,
    fingerprint: insight.fingerprint_sha256,
  };
}

function shadowToFinding(cert: Certificate): Finding {
  return {
    key: `shadow-${cert.id}`,
    kind: "shadow",
    severity: deriveShadowSeverity(cert),
    typeLabel: "Shadow certificate",
    subject: cert.subject_cn || cert.serial_number,
    secondary: cert.serial_number,
    vault:
      cert.managed_status === "managed_in_vault"
        ? "managed"
        : cert.managed_status === "imported"
        ? "tracked"
        : "shadow",
    days: cert.days_until_expiry,
    issuerDn: cert.issuer_dn,
    fingerprint: cert.fingerprint_sha256,
    serial: cert.serial_number,
    cert,
  };
}

function issuerToFinding(iss: Issuer): Finding {
  return {
    key: `issuer-${iss.id}`,
    kind: "issuer",
    severity: deriveIssuerSeverity(iss),
    typeLabel: "CA issuer",
    subject: iss.subject_cn || iss.issuer_dn,
    secondary: iss.issuer_dn,
    vault: iss.vault_pki_mount ? "managed" : "na",
    days: iss.days_until_expiry,
    issuerDn: iss.issuer_dn,
    fingerprint: iss.fingerprint_sha256,
    issuer: iss,
  };
}

function persistedToFinding(f: PersistedFinding, certs: Certificate[]): Finding {
  const cert = certs.find((c) => c.id === f.cert_id);
  const sev = (["critical", "high", "medium", "low", "info"].includes(f.severity)
    ? f.severity
    : "info") as FindingSeverity;
  return {
    key: `persisted-${f.id}`,
    kind: "persisted",
    severity: sev,
    typeLabel: humanizeInsightType(f.rule_id),
    subject: cert?.subject_cn || cert?.serial_number || f.rule_id,
    secondary: f.pack + (f.waived ? " · waived" : ""),
    vault: cert
      ? cert.managed_status === "managed_in_vault"
        ? "managed"
        : cert.managed_status === "imported"
        ? "tracked"
        : "shadow"
      : "na",
    days: cert?.days_until_expiry ?? null,
    description: f.detail || f.title,
    fingerprint: cert?.fingerprint_sha256,
    serial: cert?.serial_number,
    waived: f.waived,
    cert,
  };
}

export function buildFindings(
  report: ReportDocument,
  certs: Certificate[],
  issuers: Issuer[],
  persisted?: PersistedFinding[]
): Finding[] {
  // Prefer persisted pack+ops findings when the API returns them (M3).
  if (persisted && persisted.length > 0) {
    const rows = persisted.map((f) => persistedToFinding(f, certs));
    // Keep CA-import issuer opportunities; shadow/insight are covered by ops+packs.
    return [...rows, ...selectScanIssuers(certs, issuers).map(issuerToFinding)];
  }
  return [
    ...(report.insights ?? []).map(insightToFinding),
    ...selectShadowCerts(certs).map(shadowToFinding),
    ...selectScanIssuers(certs, issuers).map(issuerToFinding),
  ];
}

export function severityCounts(findings: Finding[]): Record<FindingSeverity, number> {
  const counts: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (f.waived) continue;
    counts[f.severity]++;
  }
  return counts;
}

export function coverageFromBlindSpot(bs: BlindSpotSummary): {
  managed: number; shadow: number; discovered: number; pct: number;
} {
  const pct = bs.discovered > 0 ? Math.round((bs.vault_managed / bs.discovered) * 100) : 0;
  return { managed: bs.vault_managed, shadow: bs.shadow, discovered: bs.discovered, pct };
}

export function findingSeverityBadgeClass(sev: FindingSeverity): string {
  return `finding-sev finding-sev-${sev}`;
}

export function sortCertificatesByRisk(certs: Certificate[], desc = true): Certificate[] {
  return [...certs].sort((a, b) => {
    const ra = a.risk_score ?? 0;
    const rb = b.risk_score ?? 0;
    return desc ? rb - ra : ra - rb;
  });
}

export function filterCertificatesByMinRisk(certs: Certificate[], minRisk: number): Certificate[] {
  return certs.filter((c) => (c.risk_score ?? 0) >= minRisk);
}
