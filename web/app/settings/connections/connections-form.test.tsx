import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  getAAPTemplateOptions,
  getConnections,
  getVaultPKIMountOptions,
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
    getVaultPKIMountOptions: vi.fn(),
    getAAPTemplateOptions: vi.fn(),
  };
});

const mockedGet = vi.mocked(getConnections);
const mockedPatch = vi.mocked(patchConnections);
const mockedTest = vi.mocked(testConnection);
const mockedMounts = vi.mocked(getVaultPKIMountOptions);
const mockedTemplates = vi.mocked(getAAPTemplateOptions);

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
  mockedMounts.mockReset();
  mockedTemplates.mockReset();
  mockedGet.mockResolvedValue(emptyView);
  mockedMounts.mockResolvedValue({ items: [] });
  mockedTemplates.mockResolvedValue({ kind: "job", items: [] });
});

describe("ConnectionsForm", () => {
  it("overrides radio inputs to compact size like checkboxes", () => {
    const css = readFileSync(resolve(__dirname, "../../globals.css"), "utf8");
    const radioRule = css.match(/input\[type=["']radio["']\]\s*\{[^}]+\}/);
    expect(radioRule?.[0]).toMatch(/width:\s*auto/);
    expect(radioRule?.[0]).toMatch(/min-height:\s*auto/);
    expect(radioRule?.[0]).toMatch(/box-shadow:\s*none/);
  });

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

  it("uses human labels for renew kind, template, and default Vault PKI mount", async () => {
    render(<ConnectionsForm />);
    expect(await screen.findByText(/^Renew with$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Template name$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Default Vault PKI mount$/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/AAP_RENEW_TEMPLATE/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/AAP_DEFAULT_MOUNT/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/AAP_RENEW_WORKFLOW/i)).not.toBeInTheDocument();
  });

  it("maps Job template / Workflow radios to renew_workflow on save", async () => {
    mockedPatch.mockResolvedValue({
      ...emptyView,
      aap: { ...emptyView.aap, renew_workflow: true },
    });

    render(<ConnectionsForm />);
    await userEvent.click(await screen.findByRole("radio", { name: /^Workflow$/i }));
    await userEvent.click(screen.getByRole("button", { name: /save aap/i }));

    expect(mockedPatch).toHaveBeenCalledWith(
      expect.objectContaining({
        aap: expect.objectContaining({ renew_workflow: true }),
      })
    );
  });

  it("shows template select when options items are non-empty", async () => {
    mockedTemplates.mockResolvedValue({
      kind: "job",
      items: [
        { id: 1, name: "CLM - Issue Certificate" },
        { id: 2, name: "CLM - Renew" },
      ],
    });

    render(<ConnectionsForm />);
    expect(await screen.findByRole("combobox", { name: /^Template name$/i })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "CLM - Renew" })).toBeInTheDocument();
  });

  it("falls back to free-text template input when options list is empty", async () => {
    mockedTemplates.mockResolvedValue({ kind: "job", items: [] });

    render(<ConnectionsForm />);
    const template = await screen.findByLabelText(/^Template name$/i);
    expect(template.tagName).toBe("INPUT");
  });

  it("shows mount select when options exist and free-text when empty, with help text", async () => {
    mockedMounts.mockResolvedValue({ items: ["pki/", "pki-int/"] });

    render(<ConnectionsForm />);
    expect(await screen.findByRole("combobox", { name: /^Default Vault PKI mount$/i })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "pki-int/" })).toBeInTheDocument();
    expect(
      screen.getByText(/Used when a certificate renew does not already set a mount/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/not an AAP resource id/i)).toBeInTheDocument();
  });

  it("falls back to free-text mount input when options list is empty", async () => {
    mockedMounts.mockResolvedValue({ items: [] });

    render(<ConnectionsForm />);
    const mount = await screen.findByLabelText(/^Default Vault PKI mount$/i);
    expect(mount.tagName).toBe("INPUT");
  });

  it("loads options on mount and reloads after successful AAP save", async () => {
    mockedPatch.mockResolvedValue(emptyView);
    mockedTemplates
      .mockResolvedValueOnce({ kind: "job", items: [] })
      .mockResolvedValueOnce({
        kind: "job",
        items: [{ id: 9, name: "After Save Template" }],
      });
    mockedMounts.mockResolvedValue({ items: [] });

    render(<ConnectionsForm />);
    await screen.findByLabelText(/^Template name$/i);

    expect(mockedMounts).toHaveBeenCalled();
    expect(mockedTemplates).toHaveBeenCalledWith("job");

    const mountsBefore = mockedMounts.mock.calls.length;
    const templatesBefore = mockedTemplates.mock.calls.length;

    await userEvent.click(screen.getByRole("button", { name: /save aap/i }));
    await waitFor(() => {
      expect(mockedMounts.mock.calls.length).toBeGreaterThan(mountsBefore);
      expect(mockedTemplates.mock.calls.length).toBeGreaterThan(templatesBefore);
    });
  });

  it("refetches AAP templates with kind=workflow when Workflow is selected", async () => {
    mockedTemplates
      .mockResolvedValueOnce({ kind: "job", items: [] })
      .mockResolvedValueOnce({
        kind: "workflow",
        items: [{ id: 4, name: "WF Renew" }],
      });

    render(<ConnectionsForm />);
    await screen.findByRole("radio", { name: /^Job template$/i });
    await userEvent.click(screen.getByRole("radio", { name: /^Workflow$/i }));

    await waitFor(() => {
      expect(mockedTemplates).toHaveBeenCalledWith("workflow");
    });
    expect(await screen.findByRole("option", { name: "WF Renew" })).toBeInTheDocument();
  });

  it("persists renew_template and default_mount from selects", async () => {
    mockedTemplates.mockResolvedValue({
      kind: "job",
      items: [
        { id: 1, name: "CLM - Issue Certificate" },
        { id: 2, name: "CLM - Renew" },
      ],
    });
    mockedMounts.mockResolvedValue({ items: ["pki/", "pki-int/"] });
    mockedPatch.mockResolvedValue(emptyView);

    render(<ConnectionsForm />);
    await userEvent.selectOptions(
      await screen.findByRole("combobox", { name: /^Template name$/i }),
      "CLM - Renew"
    );
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: /^Default Vault PKI mount$/i }),
      "pki-int/"
    );
    await userEvent.click(screen.getByRole("button", { name: /save aap/i }));

    expect(mockedPatch).toHaveBeenCalledWith(
      expect.objectContaining({
        aap: expect.objectContaining({
          renew_template: "CLM - Renew",
          default_mount: "pki-int/",
          renew_workflow: false,
        }),
      })
    );
  });
});
