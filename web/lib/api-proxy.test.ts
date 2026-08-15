import { afterEach, describe, expect, it, vi } from "vitest";
import { proxyToAPI } from "@/lib/api-proxy";
import { COOKIE_NAME, createSessionValue } from "@/lib/bff-session";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const secret = "test-session-secret-at-least-16";

async function sessionCookie(): Promise<string> {
  const value = await createSessionValue({ role: "platform_admin", secret, ttlSeconds: 3600 });
  return `${COOKIE_NAME}=${value}`;
}

describe("generic API BFF proxy", () => {
  it("rejects unauthenticated mutations without forwarding to the Go API", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://api:8080");
    vi.stubEnv("CLM_API_TOKEN", "server-only-token");
    vi.stubEnv("CLM_BFF_SESSION_SECRET", secret);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const req = new Request("http://localhost:3000/api/v1/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hostnames: ["example.com"], consent: true }),
    });
    const res = await proxyToAPI(req, { method: "POST", apiPath: "/api/v1/scans" });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "authentication required" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards mutations with server-only Authorization when session is valid", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://api:8080");
    vi.stubEnv("CLM_API_TOKEN", "server-only-token");
    vi.stubEnv("CLM_BFF_SESSION_SECRET", secret);
    vi.stubEnv("NEXT_PUBLIC_VAULT_TOKEN", "browser-leaked-token");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://evil.example:8080");

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "scan-1", status: "pending" }), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const req = new Request("http://localhost:3000/api/v1/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: await sessionCookie(),
      },
      body: JSON.stringify({ hostnames: ["example.com"], consent: true }),
    });
    const res = await proxyToAPI(req, { method: "POST", apiPath: "/api/v1/scans" });

    expect(res.status).toBe(202);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api:8080/api/v1/scans");
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer server-only-token");
    expect(JSON.parse(String(init.body))).toEqual({
      hostnames: ["example.com"],
      consent: true,
    });
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("browser-leaked-token");
    expect(url).not.toContain("evil.example");
  });

  it("allows ambient token only when CLM_BFF_INSECURE_NO_SESSION is set", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://api:8080");
    vi.stubEnv("CLM_API_TOKEN", "server-only-token");
    vi.stubEnv("CLM_BFF_INSECURE_NO_SESSION", "true");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } })
    );
    vi.stubGlobal("fetch", fetchMock);

    const req = new Request("http://localhost:3000/api/v1/certificates", { method: "GET" });
    const res = await proxyToAPI(req, { method: "GET", apiPath: "/api/v1/certificates" });
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not proxy AAP inventory through the dashboard BFF", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://api:8080");
    vi.stubEnv("CLM_API_TOKEN", "server-only-token");
    vi.stubEnv("CLM_BFF_INSECURE_NO_SESSION", "true");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const req = new Request("http://localhost:3000/api/v1/inventory", { method: "GET" });
    const res = await proxyToAPI(req, { method: "GET", apiPath: "/api/v1/inventory" });

    expect(res.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
