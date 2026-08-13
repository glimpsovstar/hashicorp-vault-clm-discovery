import { afterEach, describe, expect, it, vi } from "vitest";
import { getConnections, patchConnections, testConnection } from "@/lib/api";

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("connections client helpers", () => {
  it("testConnection POSTs {target} only to the same-origin BFF", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      jsonResponse({ ok: true, target: "vault", detail: "sys/mounts 200" })
    );
    vi.stubGlobal("fetch", fetchMock);

    await testConnection("vault");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/settings/connections/test");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ target: "vault" });
  });

  it("getConnections and patchConnections use same-origin /api/settings, not NEXT_PUBLIC_API_URL", async () => {
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://evil.example:8080");
    vi.stubEnv("NEXT_PUBLIC_VAULT_TOKEN", "must-not-be-used");
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (String(url).includes("/test")) {
        return jsonResponse({ ok: true, target: "aap", detail: "me 200" });
      }
      return jsonResponse({
        vault: { configured: false, token_set: false },
        aap: { configured: false, token_set: false },
        eda: { configured: false, token_set: false },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    await getConnections();
    await patchConnections({ vault: { addr: "https://vault.example.com:8200" } });

    const urls = fetchMock.mock.calls.map((c) => String(c[0]));
    expect(urls.every((u) => u.startsWith("/api/settings/connections"))).toBe(true);
    expect(urls.join(" ")).not.toContain("evil.example");
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("must-not-be-used");
  });
});
