"use client";

import { useEffect, useState } from "react";
import {
  getConnections,
  patchConnections,
  testConnection,
  type AAPConnectionPatch,
  type ConnectionTarget,
  type ConnectionTestResult,
  type ConnectionsView,
  type EDAConnectionPatch,
  type VaultConnectionPatch,
} from "@/lib/api";

type CardStatus = {
  saving: boolean;
  testing: boolean;
  saveMessage?: string;
  saveError?: string;
  test?: ConnectionTestResult | { error: string };
};

const emptyStatus: CardStatus = { saving: false, testing: false };

export default function ConnectionsForm() {
  const [view, setView] = useState<ConnectionsView | null>(null);
  const [loadError, setLoadError] = useState("");

  const [vaultDeployment, setVaultDeployment] = useState("self_managed");
  const [vaultAddr, setVaultAddr] = useState("");
  const [vaultNamespace, setVaultNamespace] = useState("");
  const [vaultAuth, setVaultAuth] = useState("token");
  const [vaultToken, setVaultToken] = useState("");
  const [vaultRoleId, setVaultRoleId] = useState("");
  const [vaultSecretId, setVaultSecretId] = useState("");

  const [aapUrl, setAapUrl] = useState("");
  const [aapToken, setAapToken] = useState("");
  const [aapTemplate, setAapTemplate] = useState("");
  const [aapWorkflow, setAapWorkflow] = useState(false);
  const [aapSkipTls, setAapSkipTls] = useState(false);
  const [aapMount, setAapMount] = useState("");

  const [edaUrl, setEdaUrl] = useState("");
  const [edaToken, setEdaToken] = useState("");

  const [status, setStatus] = useState<Record<ConnectionTarget, CardStatus>>({
    vault: emptyStatus,
    aap: emptyStatus,
    eda: emptyStatus,
  });

  useEffect(() => {
    let cancelled = false;
    getConnections()
      .then((data) => {
        if (!cancelled) {
          applyView(data);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setLoadError(err instanceof Error ? err.message : "Failed to load connections");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function applyView(data: ConnectionsView) {
    setView(data);
    setVaultDeployment(data.vault.deployment || "self_managed");
    setVaultAddr(data.vault.addr || "");
    setVaultNamespace(data.vault.namespace || "");
    setVaultAuth(data.vault.auth_method || "token");
    setVaultToken("");
    setVaultRoleId("");
    setVaultSecretId("");
    setAapUrl(data.aap.url || "");
    setAapToken("");
    setAapTemplate(data.aap.renew_template || "");
    setAapWorkflow(Boolean(data.aap.renew_workflow));
    setAapSkipTls(Boolean(data.aap.skip_tls_verify));
    setAapMount(data.aap.default_mount || "");
    setEdaUrl(data.eda.webhook_url || "");
    setEdaToken("");
  }

  function patchStatus(target: ConnectionTarget, next: Partial<CardStatus>) {
    setStatus((prev) => ({ ...prev, [target]: { ...prev[target], ...next } }));
  }

  function onVaultDeployment(next: string) {
    setVaultDeployment(next);
    if (next === "hcp_dedicated") {
      setVaultNamespace("admin");
    }
  }

  async function saveVault() {
    patchStatus("vault", { saving: true, saveError: undefined, saveMessage: undefined });
    const body: VaultConnectionPatch = {
      deployment: vaultDeployment,
      addr: vaultAddr,
      namespace: vaultNamespace,
      auth_method: vaultAuth,
    };
    if (vaultAuth === "token" && vaultToken) {
      body.token = vaultToken;
    }
    if (vaultAuth === "approle") {
      if (vaultRoleId) {
        body.role_id = vaultRoleId;
      }
      if (vaultSecretId) {
        body.secret_id = vaultSecretId;
      }
    }
    try {
      applyView(await patchConnections({ vault: body }));
      patchStatus("vault", { saving: false, saveMessage: "Saved." });
    } catch (err) {
      patchStatus("vault", {
        saving: false,
        saveError: err instanceof Error ? err.message : "Save failed",
      });
    }
  }

  async function saveAAP() {
    patchStatus("aap", { saving: true, saveError: undefined, saveMessage: undefined });
    const body: AAPConnectionPatch = {
      url: aapUrl,
      renew_template: aapTemplate,
      renew_workflow: aapWorkflow,
      skip_tls_verify: aapSkipTls,
      default_mount: aapMount,
    };
    if (aapToken) {
      body.token = aapToken;
    }
    try {
      applyView(await patchConnections({ aap: body }));
      patchStatus("aap", { saving: false, saveMessage: "Saved." });
    } catch (err) {
      patchStatus("aap", {
        saving: false,
        saveError: err instanceof Error ? err.message : "Save failed",
      });
    }
  }

  async function saveEDA() {
    patchStatus("eda", { saving: true, saveError: undefined, saveMessage: undefined });
    const body: EDAConnectionPatch = { webhook_url: edaUrl };
    if (edaToken) {
      body.token = edaToken;
    }
    try {
      applyView(await patchConnections({ eda: body }));
      patchStatus("eda", { saving: false, saveMessage: "Saved." });
    } catch (err) {
      patchStatus("eda", {
        saving: false,
        saveError: err instanceof Error ? err.message : "Save failed",
      });
    }
  }

  async function runTest(target: ConnectionTarget) {
    patchStatus(target, { testing: true, test: undefined });
    try {
      const result = await testConnection(target);
      patchStatus(target, { testing: false, test: result });
    } catch (err) {
      patchStatus(target, {
        testing: false,
        test: { error: err instanceof Error ? err.message : "Test failed" },
      });
    }
  }

  if (loadError) {
    return <p className="error-text">{loadError}</p>;
  }
  if (!view) {
    return <p className="muted">Loading connections…</p>;
  }

  return (
    <>
      <section className="panel">
        <div className="panel-header">
          <h2>Vault</h2>
          <ConnectionBadges configured={view.vault.configured} source={view.vault.source} />
        </div>
        <div className="panel-body">
          <div className="form-stack">
            <fieldset className="fieldset-plain">
              <legend>Deployment</legend>
              <div className="radio-row">
                <label className="checkbox-row">
                  <input
                    type="radio"
                    name="vault-deployment"
                    value="self_managed"
                    checked={vaultDeployment === "self_managed"}
                    onChange={() => onVaultDeployment("self_managed")}
                  />
                  Self-managed
                </label>
                <label className="checkbox-row">
                  <input
                    type="radio"
                    name="vault-deployment"
                    value="hcp_dedicated"
                    checked={vaultDeployment === "hcp_dedicated"}
                    onChange={() => onVaultDeployment("hcp_dedicated")}
                  />
                  HCP Dedicated
                </label>
              </div>
            </fieldset>

            <div className="form-field">
              <label htmlFor="vault-addr">
                {vaultDeployment === "hcp_dedicated" ? "Cluster URL" : "Vault address"}
              </label>
              <input
                id="vault-addr"
                value={vaultAddr}
                onChange={(e) => setVaultAddr(e.target.value)}
                placeholder="https://vault.example.com:8200"
                autoComplete="off"
              />
              {vaultDeployment === "hcp_dedicated" && (
                <p className="help-text">
                  Use the private cluster URL from the HCP portal (
                  <code>https://&lt;cluster&gt;:8200</code>), not the HCP control-plane hostname.
                </p>
              )}
            </div>

            <div className="form-field">
              <label htmlFor="vault-namespace">Namespace</label>
              <input
                id="vault-namespace"
                value={vaultNamespace}
                onChange={(e) => setVaultNamespace(e.target.value)}
                placeholder={vaultDeployment === "hcp_dedicated" ? "admin" : ""}
                autoComplete="off"
              />
            </div>

            <div className="form-field">
              <label htmlFor="vault-auth">Auth method</label>
              <select
                id="vault-auth"
                value={vaultAuth}
                onChange={(e) => setVaultAuth(e.target.value)}
              >
                <option value="token">Token</option>
                <option value="approle">AppRole</option>
              </select>
            </div>

            {vaultAuth === "token" ? (
              <SecretField
                id="vault-token"
                label="Vault token"
                value={vaultToken}
                onChange={setVaultToken}
                configured={view.vault.token_set}
                configuredLabel="Token configured"
              />
            ) : (
              <>
                <SecretField
                  id="vault-role-id"
                  label="Role ID"
                  value={vaultRoleId}
                  onChange={setVaultRoleId}
                  configured={view.vault.role_id_set}
                  configuredLabel="Role ID configured"
                />
                <SecretField
                  id="vault-secret-id"
                  label="Secret ID"
                  value={vaultSecretId}
                  onChange={setVaultSecretId}
                  configured={view.vault.secret_id_set}
                  configuredLabel="Secret ID configured"
                />
              </>
            )}
          </div>
          <CardActions
            target="vault"
            status={status.vault}
            onSave={() => void saveVault()}
            onTest={() => void runTest("vault")}
          />
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>AAP Controller</h2>
          <ConnectionBadges configured={view.aap.configured} source={view.aap.source} />
        </div>
        <div className="panel-body">
          <div className="form-stack">
            <div className="form-field">
              <label htmlFor="aap-url">AAP_URL</label>
              <input
                id="aap-url"
                value={aapUrl}
                onChange={(e) => setAapUrl(e.target.value)}
                placeholder="https://aap.example.com"
                autoComplete="off"
              />
            </div>
            <SecretField
              id="aap-token"
              label="AAP_TOKEN"
              value={aapToken}
              onChange={setAapToken}
              configured={view.aap.token_set}
              configuredLabel="Token configured"
            />
            <div className="form-field">
              <label htmlFor="aap-template">AAP_RENEW_TEMPLATE</label>
              <input
                id="aap-template"
                value={aapTemplate}
                onChange={(e) => setAapTemplate(e.target.value)}
                autoComplete="off"
              />
            </div>
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={aapWorkflow}
                onChange={(e) => setAapWorkflow(e.target.checked)}
              />
              AAP_RENEW_WORKFLOW — use a workflow job template
            </label>
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={aapSkipTls}
                onChange={(e) => setAapSkipTls(e.target.checked)}
              />
              AAP_SKIP_TLS_VERIFY — skip TLS verify (lab only)
            </label>
            <div className="form-field">
              <label htmlFor="aap-mount">AAP_DEFAULT_MOUNT</label>
              <input
                id="aap-mount"
                value={aapMount}
                onChange={(e) => setAapMount(e.target.value)}
                autoComplete="off"
              />
            </div>
          </div>
          <CardActions
            target="aap"
            status={status.aap}
            onSave={() => void saveAAP()}
            onTest={() => void runTest("aap")}
          />
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>EDA webhook</h2>
          <ConnectionBadges configured={view.eda.configured} source={view.eda.source} />
        </div>
        <div className="panel-body">
          <p className="help-text">HTTP webhook only; no message bus.</p>
          <div className="form-stack">
            <div className="form-field">
              <label htmlFor="eda-url">Webhook URL</label>
              <input
                id="eda-url"
                value={edaUrl}
                onChange={(e) => setEdaUrl(e.target.value)}
                placeholder="https://eda.example.com/webhook"
                autoComplete="off"
              />
            </div>
            <SecretField
              id="eda-token"
              label="EDA webhook token"
              value={edaToken}
              onChange={setEdaToken}
              configured={view.eda.token_set}
              configuredLabel="Token configured"
            />
          </div>
          <CardActions
            target="eda"
            status={status.eda}
            onSave={() => void saveEDA()}
            onTest={() => void runTest("eda")}
          />
        </div>
      </section>
    </>
  );
}

function ConnectionBadges({ configured, source }: { configured: boolean; source: string }) {
  return (
    <p className="help-text">
      <span className={configured ? "badge badge-success" : "badge badge-neutral"}>
        {configured ? "Configured" : "Not configured"}
      </span>{" "}
      <span className="badge badge-neutral">source: {source}</span>
    </p>
  );
}

function SecretField({
  id,
  label,
  value,
  onChange,
  configured,
  configuredLabel,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  configured: boolean;
  configuredLabel: string;
}) {
  return (
    <div className="form-field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="new-password"
        placeholder={configured ? "••••••••" : ""}
      />
      {configured && (
        <p className="help-text">{configuredLabel} — leave blank to keep the stored value.</p>
      )}
    </div>
  );
}

function CardActions({
  target,
  status,
  onSave,
  onTest,
}: {
  target: ConnectionTarget;
  status: CardStatus;
  onSave: () => void;
  onTest: () => void;
}) {
  const saveLabel = target === "aap" ? "Save AAP" : `Save ${target === "eda" ? "EDA" : "Vault"}`;
  const testLabel =
    target === "aap" ? "Test AAP connection" : `Test ${target === "eda" ? "EDA" : "Vault"} connection`;
  const test = status.test;
  return (
    <div className="form-actions">
      <button type="button" className="button button-primary" onClick={onSave} disabled={status.saving}>
        {status.saving ? "Saving…" : saveLabel}
      </button>
      <button type="button" className="button button-secondary" onClick={onTest} disabled={status.testing}>
        {status.testing ? "Testing…" : testLabel}
      </button>
      {status.saveMessage && <p className="help-text">{status.saveMessage}</p>}
      {status.saveError && <p className="error-text">{status.saveError}</p>}
      {test && "error" in test && <p className="error-text">{test.error}</p>}
      {test && "detail" in test && (
        <p className={test.ok ? "help-text" : "error-text"}>{test.detail}</p>
      )}
    </div>
  );
}
