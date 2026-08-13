import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  getConnections,
  patchConnections,
  testConnection,
  type ConnectionsView,
} from "@/lib/api";
import ConnectionsForm from "./connections-form";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    getConnections: vi.fn(),
    patchConnections: vi.fn(),
    testConnection: vi.fn(),
  };
});

const mockedGet = vi.mocked(getConnections);
const mockedPatch = vi.mocked(patchConnections);
const mockedTest = vi.mocked(testConnection);

const emptyView: ConnectionsView = {
  vault: {
    configured: false,
    source: "env",
    deployment: "self_managed",
    addr: "",
    namespace: "",
    auth_method: "token",
    token_set: false,
    role_id_set: false,
    secret_id_set: false,
  },
  aap: {
    configured: false,
    source: "env",
    url: "",
    renew_template: "CLM - Issue Certificate",
    renew_workflow: false,
    skip_tls_verify: false,
    default_mount: "pki",
    token_set: false,
  },
  eda: {
    configured: false,
    source: "env",
    webhook_url: "",
    token_set: false,
  },
};

beforeEach(() => {
  mockedGet.mockReset();
  mockedPatch.mockReset();
  mockedTest.mockReset();
  mockedGet.mockResolvedValue(emptyView);
});

describe("ConnectionsForm", () => {
  it("does not render secret values after save; shows token_set configured", async () => {
    const secret = "vault-token-should-never-appear";
    mockedPatch.mockResolvedValue({
      ...emptyView,
      vault: {
        ...emptyView.vault,
        configured: true,
        addr: "https://vault.example.com:8200",
        token_set: true,
      },
    });

    render(<ConnectionsForm />);
    await userEvent.type(await screen.findByLabelText(/cluster url|vault address/i), "https://vault.example.com:8200");
    await userEvent.type(screen.getByLabelText(/vault token/i), secret);
    await userEvent.click(screen.getByRole("button", { name: /save vault/i }));

    expect(mockedPatch).toHaveBeenCalledWith(
      expect.objectContaining({
        vault: expect.objectContaining({
          addr: "https://vault.example.com:8200",
          token: secret,
        }),
      })
    );
    expect(await screen.findByText(/token configured/i)).toBeInTheDocument();
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(secret);
  });

  it("calls testConnection with the target only when testing Vault", async () => {
    mockedGet.mockResolvedValue({
      ...emptyView,
      vault: {
        ...emptyView.vault,
        configured: true,
        addr: "https://vault.example.com:8200",
        token_set: true,
      },
    });
    mockedTest.mockResolvedValue({
      ok: true,
      target: "vault",
      detail: "sys/mounts 200; namespace=admin",
    });

    render(<ConnectionsForm />);
    await userEvent.click(await screen.findByRole("button", { name: /test vault/i }));

    expect(mockedTest).toHaveBeenCalledTimes(1);
    expect(mockedTest).toHaveBeenCalledWith("vault");
    expect(await screen.findByText(/sys\/mounts 200; namespace=admin/)).toBeInTheDocument();
  });

  it("presets namespace=admin and shows cluster URL help for HCP Dedicated", async () => {
    render(<ConnectionsForm />);
    await userEvent.click(await screen.findByRole("radio", { name: /hcp dedicated/i }));

    expect(screen.getByLabelText(/namespace/i)).toHaveValue("admin");
    expect(screen.getByText(/hcp portal/i)).toBeInTheDocument();
    expect(screen.getByText(/private cluster url/i)).toBeInTheDocument();
  });

  it("shows AppRole fields instead of the Vault token when AppRole is selected", async () => {
    render(<ConnectionsForm />);
    await userEvent.selectOptions(await screen.findByLabelText(/auth method/i), "approle");

    expect(screen.queryByLabelText(/vault token/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/role id/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/secret id/i)).toBeInTheDocument();
  });

  it("labels AAP skip TLS as lab-only and maps AAP_URL", async () => {
    render(<ConnectionsForm />);
    expect(await screen.findByLabelText(/aap_url/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/skip tls/i).closest("label")).toHaveTextContent(/lab/i);
  });

  it("states that EDA is HTTP webhook only with no message bus", async () => {
    render(<ConnectionsForm />);
    expect(await screen.findByText(/http webhook only/i)).toBeInTheDocument();
    expect(screen.getByText(/no message bus/i)).toBeInTheDocument();
  });
});
