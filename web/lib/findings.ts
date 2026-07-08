import type { Certificate, Issuer, ReportInsight, BlindSpotSummary, ReportDocument } from "@/lib/api";
import { selectShadowCerts, selectScanIssuers } from "@/lib/report";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingKind = "insight" | "shadow" | "issuer";

export type Finding = {
  key: string;
  kind: FindingKind;
  severity: FindingSeverity;
  typeLabel: string;
  subject: string;
  secondary: string;
  vault: "shadow" | "managed" | "na";
  days: number | null;
  description?: string;
  issuerDn?: string;
  fingerprint?: string;
  serial?: string;
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

// Turn a raw sc081.* / crypto.* insight type into a short human label.
function humanizeInsightType(type: string): string {
  const last = type.split(".").pop() ?? type;
  const words = last.replace(/[_-]/g, " ");
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
    vault: cert.managed_status === "managed_in_vault" ? "managed" : "shadow",
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

export function buildFindings(
  report: ReportDocument,
  certs: Certificate[],
  issuers: Issuer[]
): Finding[] {
  return [
    ...(report.insights ?? []).map(insightToFinding),
    ...selectShadowCerts(certs).map(shadowToFinding),
    ...selectScanIssuers(certs, issuers).map(issuerToFinding),
  ];
}

export function severityCounts(findings: Finding[]): Record<FindingSeverity, number> {
  const counts: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
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
