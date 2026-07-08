import type { Certificate, Issuer } from "@/lib/api";

// selectShadowCerts returns certs on the wire but not matched to Vault PKI.
// Already-tracked (`imported`) certs are kept so tracking one does not remove it
// from the list; the action button renders a disabled "Tracked" state for those.
export function selectShadowCerts(certs: Certificate[]): Certificate[] {
  return certs.filter((c) => c.managed_status !== "managed_in_vault");
}

// selectScanIssuers returns CA issuers observed in this scan, matched to the
// global issuer list by DN (the only join available without a backend change).
export function selectScanIssuers(certs: Certificate[], issuers: Issuer[]): Issuer[] {
  const dns = new Set(certs.map((c) => c.issuer_dn));
  return issuers.filter((i) => i.is_ca && dns.has(i.issuer_dn));
}
