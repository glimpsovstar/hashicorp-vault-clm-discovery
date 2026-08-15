import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import MigrateToVaultButton from "@/components/migrate-to-vault-button";
import { migrateToVault, type Certificate } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

vi.mock("@/lib/api", () => ({
  migrateToVault: vi.fn(),
  getLifecycleJob: vi.fn(),
}));

vi.mock("@/components/lifecycle-job-pending", () => ({
  default: ({ jobId }: { jobId: string }) => <div data-testid="pending">{jobId}</div>,
}));

const mockedMigrate = vi.mocked(migrateToVault);

const leaf: Certificate = {
  id: "c1",
  serial_number: "1",
  fingerprint_sha256: "fp",
  subject_cn: "app.example.com",
  subject_alt_names: [],
  issuer_dn: "CN=CA",
  not_before: "2026-01-01",
  not_after: "2027-01-01",
  days_until_expiry: 100,
  status: "valid",
  chain_status: "complete",
  hostname_matches_san: true,
  managed_status: "unmanaged",
  cert_scope: "internal",
  last_seen: "2026-08-13",
  is_ca: false,
};

beforeEach(() => {
  mockedMigrate.mockReset();
});

describe("MigrateToVaultButton", () => {
  it("shows Migrate to Vault for an unmanaged leaf and never Upload", async () => {
    render(<MigrateToVaultButton cert={leaf} />);
    expect(screen.getByRole("button", { name: /Migrate to Vault/i })).toBeInTheDocument();
    expect(screen.queryByText(/Upload/i)).not.toBeInTheDocument();
  });

  it("hides for managed_in_vault and CA", () => {
    const { rerender } = render(
      <MigrateToVaultButton cert={{ ...leaf, managed_status: "managed_in_vault" }} />
    );
    expect(screen.queryByRole("button", { name: /Migrate to Vault/i })).not.toBeInTheDocument();
    rerender(<MigrateToVaultButton cert={{ ...leaf, is_ca: true }} />);
    expect(screen.queryByRole("button", { name: /Migrate to Vault/i })).not.toBeInTheDocument();
  });

  it("consent modal explains new certificate and no private key", async () => {
    render(<MigrateToVaultButton cert={leaf} />);
    await userEvent.click(screen.getByRole("button", { name: /Migrate to Vault/i }));
    expect(screen.getByText(/new certificate/i)).toBeInTheDocument();
    expect(screen.getByText(/no private key/i)).toBeInTheDocument();
  });
});
