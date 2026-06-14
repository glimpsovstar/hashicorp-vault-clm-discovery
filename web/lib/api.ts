function getApiBaseUrl(): string {
  // Server components (Docker): reach API via compose service name.
  if (typeof window === "undefined") {
    return (
      process.env.API_INTERNAL_URL ||
      process.env.NEXT_PUBLIC_API_URL ||
      "http://localhost:8080"
    );
  }
  // Browser: use host-mapped API port.
  return process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";
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
  observation_count?: number;
  last_seen: string;
  pem?: string;
  owner?: string;
  team?: string;
  environment?: string;
  tags?: string[];
};

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

export type Scan = {
  id: string;
  status: string;
  cidrs: string[];
  hostnames?: string[];
  ports: number[];
  concurrency: number;
  targets_total: number;
  targets_scanned: number;
  certs_found: number;
  started_at?: string;
  finished_at?: string;
  error?: string;
  created_at: string;
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
};

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${getApiBaseUrl()}${path}`, {
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

async function fetchVoid(path: string, init?: RequestInit): Promise<void> {
  const res = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers: {
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

export function getCertificate(id: string) {
  return fetchJSON<{ certificate: Certificate; observations: Observation[] }>(`/api/v1/certificates/${id}`);
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

export function listIssuers() {
  return fetchJSON<{ items: Issuer[] }>("/api/v1/issuers");
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
