import { describe, it, expect } from "vitest";
import { selectShadowCerts, selectScanIssuers } from "./report";
import type { Certificate, Issuer } from "./api";

function cert(over: Partial<Certificate>): Certificate {
  return {
    id: "c",
    serial_number: "1",
    fingerprint_sha256: "f",
    subject_alt_names: [],
    issuer_dn: "CN=Test CA",
    not_before: "",
    not_after: "",
    days_until_expiry: 10,
    status: "valid",
    chain_status: "complete",
    hostname_matches_san: true,
    managed_status: "unmanaged",
    cert_scope: "external",
    last_seen: "",
    ...over,
  };
}

function issuer(over: Partial<Issuer>): Issuer {
  return {
    id: "i",
    fingerprint_sha256: "f",
    issuer_dn: "CN=Test CA",
    not_after: "",
    days_until_expiry: 100,
    status: "valid",
    is_ca: true,
    ...over,
  };
}

describe("selectShadowCerts", () => {
  it("includes unmanaged and imported, excludes managed_in_vault", () => {
    const certs = [
      cert({ id: "a", managed_status: "unmanaged" }),
      cert({ id: "b", managed_status: "imported" }),
      cert({ id: "c", managed_status: "managed_in_vault" }),
    ];
    expect(selectShadowCerts(certs).map((c) => c.id)).toEqual(["a", "b"]);
  });

  it("returns an empty array when everything is managed in Vault", () => {
    const certs = [cert({ managed_status: "managed_in_vault" })];
    expect(selectShadowCerts(certs)).toEqual([]);
  });
});

describe("selectScanIssuers", () => {
  it("keeps CA issuers whose DN was seen in the scan", () => {
    const certs = [cert({ issuer_dn: "CN=Seen CA" })];
    const issuers = [
      issuer({ id: "seen", issuer_dn: "CN=Seen CA", is_ca: true }),
      issuer({ id: "unseen", issuer_dn: "CN=Other CA", is_ca: true }),
      issuer({ id: "leaf", issuer_dn: "CN=Seen CA", is_ca: false }),
    ];
    expect(selectScanIssuers(certs, issuers).map((i) => i.id)).toEqual(["seen"]);
  });

  it("returns an empty array when no CA issuer matches", () => {
    const certs = [cert({ issuer_dn: "CN=Only Leaf" })];
    const issuers = [issuer({ id: "x", issuer_dn: "CN=Different", is_ca: true })];
    expect(selectScanIssuers(certs, issuers)).toEqual([]);
  });
});
