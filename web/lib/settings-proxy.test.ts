import { afterEach, describe, expect, it, vi } from "vitest";
import { proxySettings } from "@/lib/settings-proxy";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("settings BFF proxy", () => {
  it("forwards to API_INTERNAL_URL with server-only Authorization", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://api:8080");
    vi.stubEnv("CLM_API_TOKEN", "server-only-token");
    vi.stubEnv("CLM_BFF_INSECURE_NO_SESSION", "true");
    vi.stubEnv("NEXT_PUBLIC_VAULT_TOKEN", "browser-leaked-token");
    vi.stubEnv("NEXT_PUBLIC_AAP_TOKEN", "browser-aap-token");

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ vault: { token_set: true } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const req = new Request("http://localhost/api/settings/connections", { method: "GET" });
    const res = await proxySettings(req, { method: "GET" });

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api:8080/api/v1/settings/connections");
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer server-only-token");
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("browser-leaked-token");
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("browser-aap-token");
  });

  it("POSTs the test body through unchanged to /test", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://api:8080");
    vi.stubEnv("CLM_BFF_INSECURE_NO_SESSION", "true");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true, target: "eda", detail: "webhook 2xx" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const req = new Request("http://localhost/api/settings/connections/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: "eda" }),
    });
    await proxySettings(req, { method: "POST", suffix: "/test" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api:8080/api/v1/settings/connections/test");
    expect(JSON.parse(String(init.body))).toEqual({ target: "eda" });
  });
});
