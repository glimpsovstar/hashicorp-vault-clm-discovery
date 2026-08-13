import { afterEach, describe, expect, it, vi } from "vitest";
import { apiRequestHeaders, resolveApiBaseUrl } from "@/lib/api-request";
import { createScan } from "@/lib/api";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("dashboard API request targeting", () => {
  it("uses the same-origin BFF in the browser, not :8080", () => {
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://evil.example:8080");
    expect(resolveApiBaseUrl(true)).toBe("");
  });

  it("uses API_INTERNAL_URL on the server", () => {
    vi.stubEnv("API_INTERNAL_URL", "http://api:8080");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://localhost:8080");
    expect(resolveApiBaseUrl(false)).toBe("http://api:8080");
  });

  it("attaches CLM_API_TOKEN only on the server", () => {
    vi.stubEnv("CLM_API_TOKEN", "server-only-token");
    vi.stubEnv("NEXT_PUBLIC_VAULT_TOKEN", "must-not-be-used");

    const server = new Headers(apiRequestHeaders(false));
    expect(server.get("Authorization")).toBe("Bearer server-only-token");

    const browser = new Headers(apiRequestHeaders(true));
    expect(browser.get("Authorization")).toBeNull();
  });

  it("createScan from the browser hits same-origin /api/v1/scans without a token", async () => {
    vi.stubEnv("CLM_API_TOKEN", "server-only-token");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://localhost:8080");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "scan-1", status: "pending" }), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await createScan({ hostnames: ["example.com"], consent: true });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toBe("/api/v1/scans");
    expect(String(url)).not.toContain("localhost:8080");
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBeNull();
  });
});
