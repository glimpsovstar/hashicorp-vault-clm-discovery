import { apiRequestHeaders, resolveApiBaseUrl } from "@/lib/api-request";

function isBrowser(): boolean {
  return typeof window !== "undefined";
}

function getApiBaseUrl(): string {
  return resolveApiBaseUrl(isBrowser());
}

export type Certificate = {
  id: string;
  serial_number: string;
  fingerprint_sha256: string;
  subject_cn?: string;
  subject_alt_names: string[];
  issuer_dn: string;
  not_before: string;
  not_after: string;
  days_until_expiry: number;
  status: string;
  chain_status: string;
  hostname_matches_san: boolean;
  managed_status: string;
  cert_scope: string;
  is_ca?: boolean;
  vault_pki_mount?: string | null;
  vault_issuer_ref?: string | null;
  revocation_status?: string | null;
  observation_count?: number;
  last_seen: string;
  pem?: string;
  owner?: string;
  team?: string;
  environment?: string;
  tags?: string[];
  risk_score?: number;
  risk_reasons?: RiskReason[];
  pqc_tag?: "classic" | "hybrid" | "pqc" | "unknown";
};

export type RiskReason = {
  rule_id: string;
  pack: string;
  severity: string;
  title: string;
  score: number;
  waived?: boolean;
};

export type PersistedFinding = {
  id: string;
  cert_id: string;
  rule_id: string;
  pack: string;
  severity: FindingSeverityLike;
  title: string;
  detail: string;
  status: string;
  waived: boolean;
};

type FindingSeverityLike = "critical" | "high" | "medium" | "low" | "info";

export type Observation = {
  id: string;
  ip: string;
  port: number;
  hostname?: string;
  sni?: string;
  tls_version?: string;
  cipher_suite?: string;
  observed_at: string;
};

export type TargetFailureSample = {
  ip: string;
  port: number;
  hostname?: string;
  sni?: string;
  reason: string;
  kind: "probe" | "upsert";
};

export type Scan = {
  id: string;
  status: string;
  cidrs: string[];
  hostnames?: string[];
  ports: number[];
  concurrency: number;
  targets_total: number;
  targets_scanned: number;
  targets_succeeded: number;
  targets_failed: number;
  certs_found: number;
  upsert_failures: number;
  expansion_warnings?: string[];
  failure_samples?: TargetFailureSample[];
  started_at?: string;
  finished_at?: string;
  error?: string;
  created_at: string;
};

export type BlindSpotSummary = {
  vault_managed: number;
  discovered: number;
  shadow: number;
  sc081_violations: number;
};

export type ReconcileSummary = {
  mounts_scanned: number;
  vault_certs_read: number;
  matched: number;
  unmatched_clm: number;
  status: "ok" | "partial" | "failed";
  errors: string[];
};

export type ReportInsight = {
  category: string;
  type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  recommendation: string;
  subject_cn?: string;
  fingerprint_sha256?: string;
  issuer_dn?: string;
  description: string;
  tags?: string[];
};

export type ReportRecommendation = {
  code: string;
  count: number;
  phase: string;
  title: string;
};

// ReportDocument mirrors the Go report.Document JSON (report_version 0.2.0). Only
// the fields the dashboard renders are typed; the rest of the payload is ignored.
export type ReportDocument = {
  report_version: string;
  generated_at: string;
  scan_id: string;
  scan_status: string;
  blind_spot: BlindSpotSummary;
  cert_health: {
    total: number;
    by_status: Record<string, number>;
    expiry_buckets: {
      expired: number;
      within_7d: number;
      within_30d: number;
      within_90d: number;
      beyond_90d: number;
    };
  };
  expiry_risk: {
    within_7d: number;
    within_30d: number;
    within_90d: number;
  };
  scope_governance: {
    by_scope: Record<string, number>;
    by_managed_status: Record<string, number>;
    owner_coverage: { with_owner: number; total: number };
  };
  insights: ReportInsight[];
  recommendations: ReportRecommendation[];
};

export type Issuer = {
  id: string;
  fingerprint_sha256: string;
  subject_cn?: string;
  issuer_dn: string;
  not_after: string;
  days_until_expiry: number;
  status: string;
  is_ca: boolean;
  vault_issuer_ref?: string | null;
  vault_pki_mount?: string | null;
};

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers: {
      ...apiRequestHeaders(isBrowser()),
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || res.statusText);
  }
  return res.json();
}

async function fetchVoid(path: string, init?: RequestInit): Promise<void> {
  const res = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers: {
      ...apiRequestHeaders(isBrowser()),
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || res.statusText);
  }
}

export function listCertificates(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return fetchJSON<{ items: Certificate[]; total: number }>(`/api/v1/certificates?${qs}`);
}

export function listScanFindings(scanId: string) {
  return fetchJSON<{ items: PersistedFinding[] }>(`/api/v1/scans/${scanId}/findings`);
}

export function listCertFindings(certId: string) {
  return fetchJSON<{ items: PersistedFinding[] }>(`/api/v1/certificates/${certId}/findings`);
}

export function getPQCInventory() {
  return fetchJSON<{ pqc_tags: Record<string, number> }>(`/api/v1/inventory/pqc`);
}

export function getCertificate(id: string) {
  return fetchJSON<{ certificate: Certificate; observations: Observation[] }>(`/api/v1/certificates/${id}`);
}

export type ChooseResult = {
  code: string;
  title: string;
  rationale: string;
  cta: string;
};

// getChoose returns the recommended Choose-phase action for a certificate.
export function getChoose(id: string) {
  return fetchJSON<ChooseResult>(`/api/v1/certificates/${id}/choose`);
}

export type RevocationResult = {
  status: string;
  source: string;
  verified: boolean;
  revoked_at?: string | null;
  crl_url?: string;
};

// checkRevocation runs an on-demand CRL revocation check for a certificate.
export function checkRevocation(id: string) {
  return fetchJSON<RevocationResult>(`/api/v1/certificates/${id}/revocation-check`, {
    method: "POST",
  });
}

export type RenewalArtifact = {
  filename: string;
  language: string;
  content: string;
};

// getRenewalKit generates Mode C reissue+deploy artifacts (vault-agent / AAP).
export function getRenewalKit(
  id: string,
  params: { target: string; role: string; mount?: string; service?: string }
) {
  const qs = new URLSearchParams({ target: params.target, role: params.role });
  if (params.mount) qs.set("mount", params.mount);
  if (params.service) qs.set("service", params.service);
  return fetchJSON<{ target: string; artifacts: RenewalArtifact[] }>(
    `/api/v1/certificates/${id}/renewal-kit?${qs.toString()}`
  );
}

export function listScans() {
  return fetchJSON<{ items: Scan[] }>("/api/v1/scans");
}

export function getScan(id: string) {
  return fetchJSON<Scan>(`/api/v1/scans/${id}`);
}

export function listScanCertificates(scanId: string) {
  return fetchJSON<{ items: Certificate[]; total: number }>(`/api/v1/scans/${scanId}/certificates`);
}

export function deleteScan(id: string) {
  return fetchVoid(`/api/v1/scans/${id}`, { method: "DELETE" });
}

export function deleteCertificate(id: string) {
  return fetchVoid(`/api/v1/certificates/${id}`, { method: "DELETE" });
}

export function deleteIssuer(id: string) {
  return fetchVoid(`/api/v1/issuers/${id}`, { method: "DELETE" });
}

// importIssuer implements mode B: write the issuer's CA bundle into a Vault PKI
// mount. Requires explicit consent and the target mount.
export function importIssuer(id: string, mount: string) {
  return fetchJSON<Issuer>(`/api/v1/issuers/${id}/import`, {
    method: "POST",
    body: JSON.stringify({ consent: true, mount }),
  });
}

export function createScan(body: {
  cidrs?: string[];
  hostnames?: string[];
  ports?: number[];
  concurrency?: number;
  consent: boolean;
}) {
  return fetchJSON<Scan>("/api/v1/scans", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function patchCertificate(id: string, body: Partial<Pick<Certificate, "owner" | "team" | "environment" | "tags">>) {
  return fetchJSON<Certificate>(`/api/v1/certificates/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

// catalogImport implements mode A: track the cert in CLM (managed_status=imported)
// without any Vault write. Requires explicit consent per the API contract.
export function catalogImport(id: string) {
  return fetchJSON<Certificate>(`/api/v1/certificates/${id}/catalog-import`, {
    method: "POST",
    body: JSON.stringify({ consent: true }),
  });
}

export type LifecycleJob = {
  id: string;
  kind?: string;
  job_kind?: "migrate" | "renew" | string;
  status: string;
  user_status: "Pending" | "Verified" | "Timed out" | "Failed" | string;
  aap_job_id?: number | null;
  next_verify_at?: string | null;
  timeout_at: string;
  verify_attempt: number;
};

export type MigrateLaunchResponse = {
  status: string;
  user_status?: string;
  lifecycle_job_id: string;
  timeout_at?: string;
  next_verify_at?: string | null;
};

export function migrateToVault(
  id: string,
  body: {
    consent: true;
    mount: string;
    role: string;
    service?: string;
    target_hosts?: string;
    ttl?: string;
    alt_names?: string;
  }
) {
  return fetchJSON<MigrateLaunchResponse>(`/api/v1/certificates/${id}/migrate`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function getLifecycleJob(id: string) {
  return fetchJSON<LifecycleJob>(`/api/v1/lifecycle-jobs/${id}`);
}

export function listIssuers() {
  return fetchJSON<{ items: Issuer[] }>("/api/v1/issuers");
}

export function fetchBlindSpot(scanId: string) {
  return fetchJSON<BlindSpotSummary>(`/api/v1/scans/${scanId}/blindspot`);
}

// fetchReport returns the structured environment report the report page renders.
export function fetchReport(scanId: string) {
  return fetchJSON<ReportDocument>(`/api/v1/scans/${scanId}/report?format=json`);
}

export function triggerReconcile() {
  return fetchJSON<ReconcileSummary>("/api/v1/reconcile", { method: "POST" });
}

export type ConnectionTarget = "vault" | "aap" | "eda";

export type VaultConnectionView = {
  configured: boolean;
  source: string;
  deployment: string;
  addr: string;
  namespace: string;
  auth_method: string;
  token_set: boolean;
  role_id_set: boolean;
  secret_id_set: boolean;
};

export type AAPConnectionView = {
  configured: boolean;
  source: string;
  url: string;
  renew_template: string;
  renew_workflow: boolean;
  skip_tls_verify: boolean;
  default_mount: string;
  token_set: boolean;
};

export type EDAConnectionView = {
  configured: boolean;
  source: string;
  webhook_url: string;
  token_set: boolean;
};

export type ConnectionsView = {
  vault: VaultConnectionView;
  aap: AAPConnectionView;
  eda: EDAConnectionView;
};

export type ConnectionTestResult = {
  ok: boolean;
  target: string;
  detail: string;
};

export type VaultConnectionPatch = {
  deployment?: string;
  addr?: string;
  namespace?: string;
  auth_method?: string;
  token?: string;
  role_id?: string;
  secret_id?: string;
};

export type AAPConnectionPatch = {
  url?: string;
  renew_template?: string;
  renew_workflow?: boolean;
  skip_tls_verify?: boolean;
  default_mount?: string;
  token?: string;
};

export type EDAConnectionPatch = {
  webhook_url?: string;
  token?: string;
};

export type ConnectionsPatch = {
  vault?: VaultConnectionPatch;
  aap?: AAPConnectionPatch;
  eda?: EDAConnectionPatch;
};

// Same-origin BFF only — never NEXT_PUBLIC_API_URL / NEXT_PUBLIC_* secrets.
async function fetchSameOrigin<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || res.statusText);
  }
  return res.json();
}

export function getConnections() {
  return fetchSameOrigin<ConnectionsView>("/api/settings/connections");
}

export function patchConnections(body: ConnectionsPatch) {
  return fetchSameOrigin<ConnectionsView>("/api/settings/connections", {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function testConnection(target: ConnectionTarget) {
  return fetchSameOrigin<ConnectionTestResult>("/api/settings/connections/test", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export type VaultPKIMountOptions = {
  items: string[];
  detail?: string;
};

export type AAPTemplateOption = {
  id: number;
  name: string;
};

export type AAPTemplateOptions = {
  kind: string;
  items: AAPTemplateOption[];
  detail?: string;
};

export type AAPTemplateKind = "job" | "workflow";

// Same-origin BFF catch-all — never NEXT_PUBLIC_* secrets or direct Vault/AAP.
export function getVaultPKIMountOptions() {
  return fetchSameOrigin<VaultPKIMountOptions>(
    "/api/v1/settings/connections/options/vault-pki-mounts"
  );
}

export function getAAPTemplateOptions(kind: AAPTemplateKind) {
  return fetchSameOrigin<AAPTemplateOptions>(
    `/api/v1/settings/connections/options/aap-templates?kind=${kind}`
  );
}

export async function downloadReport(scanId: string, format: "markdown" | "json" | "csv" = "markdown") {
  const res = await fetch(
    `${getApiBaseUrl()}/api/v1/scans/${scanId}/report?format=${format}`,
    { headers: apiRequestHeaders(isBrowser()), cache: "no-store" }
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || res.statusText);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const ext = format === "markdown" ? "md" : format;
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `scan-${scanId.slice(0, 8)}-report.${ext}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function severityBadgeClass(severity: string): string {
  switch (severity) {
    case "critical":
    case "high":
      return "badge badge-critical";
    case "medium":
      return "badge badge-warning";
    case "low":
      return "badge badge-neutral";
    default:
      return "badge badge-neutral";
  }
}

export function scanStatusBadgeClass(status: string): string {
  switch (status) {
    case "completed":
      return "badge badge-success";
    case "running":
      return "badge badge-warning";
    case "failed":
      return "badge badge-critical";
    default:
      return "badge badge-neutral";
  }
}

export function statusBadgeClass(status: string): string {
  switch (status) {
    case "valid":
      return "badge badge-success";
    case "expiring_soon":
      return "badge badge-warning";
    case "expired":
    case "revoked":
      return "badge badge-critical";
    default:
      return "badge badge-neutral";
  }
}

export function expiryBadgeClass(status: string): string {
  if (status === "expired" || status === "revoked") {
    return "badge badge-critical";
  }
  return "badge badge-success";
}

export function expiryLabel(status: string): string {
  if (status === "expired" || status === "revoked") {
    return "Expired";
  }
  return "Active";
}

export function vaultConnectedBadgeClass(managedStatus: string): string {
  return managedStatus === "managed_in_vault" ? "badge badge-success" : "badge badge-neutral";
}

export function vaultConnectedLabel(managedStatus: string): string {
  return managedStatus === "managed_in_vault" ? "Connected" : "Not connected";
}

export function vaultImportedBadgeClass(managedStatus: string): string {
  return managedStatus === "imported" ? "badge badge-warning" : "badge badge-neutral";
}

export function vaultImportedLabel(managedStatus: string): string {
  return managedStatus === "imported" ? "Imported" : "Not imported";
}

export function certScopeBadgeClass(scope: string): string {
  return scope === "internal" ? "badge badge-neutral" : "badge badge-success";
}

export function certScopeLabel(scope: string): string {
  return scope === "internal" ? "Internal" : "External";
}
