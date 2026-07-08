import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Finding } from "@/lib/findings";

// The row actions call the API + router; stub them so the explorer renders in isolation.
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));
vi.mock("@/lib/api", async (orig) => ({ ...(await orig<typeof import("@/lib/api")>()), catalogImport: vi.fn(), importIssuer: vi.fn() }));

import ReportExplorer from "./report-explorer";

const F: Finding[] = [
  { key: "i1", kind: "insight", severity: "critical", typeLabel: "Expiry critical", subject: "api.pay", secondary: "compliance", vault: "na", days: null, description: "Expiring soon", fingerprint: "abc123" },
  { key: "s1", kind: "shadow", severity: "high", typeLabel: "Shadow certificate", subject: "legacy.vpn", secondary: "SER-1", vault: "shadow", days: 12, issuerDn: "CN=Legacy", fingerprint: "def456", serial: "SER-1",
    cert: { id: "s1", serial_number: "SER-1", fingerprint_sha256: "def456", subject_alt_names: [], issuer_dn: "CN=Legacy", not_before: "", not_after: "", days_until_expiry: 12, status: "valid", chain_status: "complete", hostname_matches_san: true, managed_status: "unmanaged", cert_scope: "external", last_seen: "2026-07-04T00:00:00Z" } },
  { key: "c1", kind: "issuer", severity: "low", typeLabel: "CA issuer", subject: "Acme CA", secondary: "CN=Acme CA", vault: "na", days: 300, issuerDn: "CN=Acme CA", fingerprint: "aa11",
    issuer: { id: "c1", fingerprint_sha256: "aa11", issuer_dn: "CN=Acme CA", not_after: "", days_until_expiry: 300, status: "valid", is_ca: true } },
];
const COVERAGE = { managed: 34, shadow: 16, discovered: 50, pct: 68 };

describe("ReportExplorer", () => {
  it("renders the coverage meter and every finding row", () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    expect(screen.getByText("68%")).toBeInTheDocument();
    expect(screen.getByText("api.pay")).toBeInTheDocument();
    expect(screen.getByText("legacy.vpn")).toBeInTheDocument();
    expect(screen.getByText("Acme CA")).toBeInTheDocument();
  });

  it("filters to a single severity when its chip is toggled", async () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    await userEvent.click(screen.getByRole("button", { name: /^Critical/ }));
    expect(screen.getByText("api.pay")).toBeInTheDocument();
    expect(screen.queryByText("legacy.vpn")).not.toBeInTheDocument();
  });

  it("filters by search over subject", async () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    await userEvent.type(screen.getByRole("searchbox"), "legacy");
    expect(screen.getByText("legacy.vpn")).toBeInTheDocument();
    expect(screen.queryByText("api.pay")).not.toBeInTheDocument();
  });

  it("reveals drill-in detail when a row is opened", async () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    await userEvent.click(screen.getByText("legacy.vpn"));
    expect(screen.getByText("CN=Legacy")).toBeInTheDocument(); // issuer DN in detail
    expect(screen.getByRole("button", { name: /Track in CLM/ })).toBeInTheDocument();
  });

  it("shows an empty state when filters match nothing", async () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    await userEvent.type(screen.getByRole("searchbox"), "zzzznope");
    expect(screen.getByText(/No findings match/i)).toBeInTheDocument();
  });
});
