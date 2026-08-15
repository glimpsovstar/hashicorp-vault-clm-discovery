import { afterEach, describe, expect, it, vi } from "vitest";
import { POST as login } from "@/app/api/auth/login/route";
import { POST as logout } from "@/app/api/auth/logout/route";
import { GET as me } from "@/app/api/auth/me/route";
import { COOKIE_NAME, createSessionValue } from "@/lib/bff-session";
import { buildOidcAuthorizeUrl } from "@/lib/bff-oidc";

afterEach(() => {
  vi.unstubAllEnvs();
});

const secret = "test-session-secret-at-least-16";

describe("auth login/logout/me", () => {
  it("rejects wrong password", async () => {
    vi.stubEnv("CLM_BFF_SESSION_SECRET", secret);
    vi.stubEnv("CLM_BFF_DEMO_PASSWORD", "correct-horse");
    const res = await login(
      new Request("http://localhost/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "wrong" }),
      })
    );
    expect(res.status).toBe(401);
  });

  it("sets session cookie on demo password login", async () => {
    vi.stubEnv("CLM_BFF_SESSION_SECRET", secret);
    vi.stubEnv("CLM_BFF_DEMO_PASSWORD", "correct-horse");
    const res = await login(
      new Request("http://localhost/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "correct-horse" }),
      })
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ role: "platform_admin" });
    const setCookie = res.headers.get("Set-Cookie") || "";
    expect(setCookie).toContain(`${COOKIE_NAME}=`);
    expect(setCookie).toContain("HttpOnly");
  });

  it("returns role from me when session cookie present", async () => {
    vi.stubEnv("CLM_BFF_SESSION_SECRET", secret);
    const value = await createSessionValue({ role: "platform_admin", secret, ttlSeconds: 60 });
    const res = await me(
      new Request("http://localhost/api/auth/me", {
        headers: { Cookie: `${COOKIE_NAME}=${value}` },
      })
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ authenticated: true, role: "platform_admin" });
  });

  it("clears cookie on logout", async () => {
    const res = await logout(new Request("http://localhost/api/auth/logout", { method: "POST" }));
    expect(res.status).toBe(200);
    expect(res.headers.get("Set-Cookie") || "").toContain("Max-Age=0");
  });
});

describe("oidc authorize url", () => {
  it("builds authorization URL with state and PKCE challenge", () => {
    const url = buildOidcAuthorizeUrl({
      issuer: "https://idp.example.com",
      clientId: "clm-dashboard",
      redirectUri: "http://localhost:3000/api/auth/oidc/callback",
      state: "state123",
      codeChallenge: "challenge456",
    });
    expect(url).toContain("https://idp.example.com/authorize?");
    expect(url).toContain("client_id=clm-dashboard");
    expect(url).toContain("state=state123");
    expect(url).toContain("code_challenge=challenge456");
    expect(url).toContain("code_challenge_method=S256");
    expect(url).toContain("response_type=code");
  });
});
