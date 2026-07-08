import { describe, it, expect } from "vitest";
import {
  deriveShadowSeverity,
  deriveIssuerSeverity,
  buildFindings,
  severityCounts,
  coverageFromBlindSpot,
  findingSeverityBadgeClass,
} from "./findings";
import type { Certificate, Issuer, ReportDocument } from "./api";

function cert(over: Partial<Certificate>): Certificate {
  return {
    id: "c", serial_number: "1", fingerprint_sha256: "f", subject_alt_names: [],
    issuer_dn: "CN=Test CA", not_before: "", not_after: "", days_until_expiry: 60,
    status: "valid", chain_status: "complete", hostname_matches_san: true,
    managed_status: "unmanaged", cert_scope: "external", last_seen: "2026-07-01T00:00:00Z",
    ...over,
  };
}
function issuer(over: Partial<Issuer>): Issuer {
  return {
    id: "i", fingerprint_sha256: "f", issuer_dn: "CN=Test CA", not_after: "",
    days_until_expiry: 100, status: "valid", is_ca: true, ...over,
  };
}
function report(over: Partial<ReportDocument> = {}): ReportDocument {
  return {
    report_version: "0.2.0", generated_at: "2026-07-09T00:00:00Z", scan_id: "s",
    scan_status: "completed",
    blind_spot: { vault_managed: 34, discovered: 50, shadow: 16, sc081_violations: 4 },
    cert_health: { total: 50, by_status: {}, expiry_buckets: { expired: 0, within_7d: 0, within_30d: 0, within_90d: 0, beyond_90d: 0 } },
    expiry_risk: { within_7d: 0, within_30d: 0, within_90d: 0 },
    scope_governance: { by_scope: {}, by_managed_status: {}, owner_coverage: { with_owner: 0, total: 0 } },
    insights: [], recommendations: [], ...over,
  };
}

describe("deriveShadowSeverity", () => {
  it("expired -> critical", () => {
    expect(deriveShadowSeverity(cert({ status: "expired", days_until_expiry: -1 }))).toBe("critical");
  });
  it("<=7 days -> critical", () => {
    expect(deriveShadowSeverity(cert({ days_until_expiry: 5 }))).toBe("critical");
  });
  it("<=30 days -> high", () => {
    expect(deriveShadowSeverity(cert({ days_until_expiry: 20 }))).toBe("high");
  });
  it("otherwise -> medium (unmanaged is inherently notable)", () => {
    expect(deriveShadowSeverity(cert({ days_until_expiry: 200 }))).toBe("medium");
  });
});

describe("deriveIssuerSeverity", () => {
  it("<=30 days -> high", () => {
    expect(deriveIssuerSeverity(issuer({ days_until_expiry: 10 }))).toBe("high");
  });
  it("otherwise -> low", () => {
    expect(deriveIssuerSeverity(issuer({ days_until_expiry: 300 }))).toBe("low");
  });
});

describe("buildFindings", () => {
  it("folds insights, shadow certs, and issuers into one list tagged by kind", () => {
    const certs = [
      cert({ id: "shadow1", subject_cn: "app.db", managed_status: "unmanaged", days_until_expiry: 3, issuer_dn: "CN=Seen CA" }),
      cert({ id: "managed1", managed_status: "managed_in_vault", issuer_dn: "CN=Seen CA" }),
    ];
    const issuers = [issuer({ id: "ca1", issuer_dn: "CN=Seen CA", is_ca: true, days_until_expiry: 300 })];
    const rep = report({
      insights: [{ category: "compliance", type: "sc081.expiry.critical", severity: "critical", recommendation: "renew", description: "Expiring", subject_cn: "api.pay" }],
    });
    const findings = buildFindings(rep, certs, issuers);
    const kinds = findings.map((f) => f.kind);
    expect(kinds).toContain("insight");
    expect(kinds).toContain("shadow");
    expect(kinds).toContain("issuer");
    // managed cert is NOT a shadow finding
    expect(findings.some((f) => f.kind === "shadow" && f.cert?.id === "managed1")).toBe(false);
    // shadow cert attaches its cert for the action; severity derived (3 days -> critical)
    const s = findings.find((f) => f.kind === "shadow" && f.cert?.id === "shadow1")!;
    expect(s.cert).toBeDefined();
    expect(s.severity).toBe("critical");
    expect(s.subject).toBe("app.db");
    // issuer attaches its issuer for the action
    const ca = findings.find((f) => f.kind === "issuer")!;
    expect(ca.issuer?.id).toBe("ca1");
  });

  it("gives every finding a unique key", () => {
    const certs = [cert({ id: "a", managed_status: "unmanaged" }), cert({ id: "b", managed_status: "unmanaged" })];
    const findings = buildFindings(report(), certs, []);
    const keys = findings.map((f) => f.key);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("severityCounts", () => {
  it("counts by severity including zeros", () => {
    const certs = [cert({ id: "a", managed_status: "unmanaged", days_until_expiry: 3 })]; // critical
    const counts = severityCounts(buildFindings(report(), certs, []));
    expect(counts.critical).toBe(1);
    expect(counts.info).toBe(0);
  });
});

describe("coverageFromBlindSpot", () => {
  it("computes managed percentage of discovered", () => {
    expect(coverageFromBlindSpot({ vault_managed: 34, discovered: 50, shadow: 16, sc081_violations: 4 }).pct).toBe(68);
  });
  it("is 0% when nothing was discovered", () => {
    expect(coverageFromBlindSpot({ vault_managed: 0, discovered: 0, shadow: 0, sc081_violations: 0 }).pct).toBe(0);
  });
});

describe("findingSeverityBadgeClass", () => {
  it("maps severity to a per-severity class", () => {
    expect(findingSeverityBadgeClass("critical")).toBe("finding-sev finding-sev-critical");
    expect(findingSeverityBadgeClass("info")).toBe("finding-sev finding-sev-info");
  });
});
