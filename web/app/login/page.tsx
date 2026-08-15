"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string };
        setError(body.error || "Login failed");
        return;
      }
      router.push("/");
      router.refresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel" style={{ maxWidth: 420, margin: "2rem auto" }}>
      <h1 className="hds-typography-display-300">Operator login</h1>
      <p className="muted">
        Sign in to use the dashboard BFF. Demo compose uses the demo password from{" "}
        <code>CLM_BFF_DEMO_PASSWORD</code>.
      </p>
      <form onSubmit={onSubmit} className="stack" style={{ gap: "0.75rem", marginTop: "1rem" }}>
        <label className="field">
          <span>Password</span>
          <input
            type="password"
            name="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        {error ? <p className="error-text">{error}</p> : null}
        <button type="submit" className="button button-primary" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className="muted" style={{ marginTop: "1rem" }}>
        Optional OIDC:{" "}
        <a href="/api/auth/oidc/start">Sign in with OIDC</a> (when{" "}
        <code>CLM_BFF_OIDC_*</code> is set).
      </p>
    </div>
  );
}
