import { afterEach, describe, expect, it, vi } from "vitest";
import {
  COOKIE_NAME,
  createSessionValue,
  parseSessionCookie,
  sessionFromRequest,
  verifySessionValue,
} from "@/lib/bff-session";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("bff-session", () => {
  const secret = "test-session-secret-at-least-16";

  it("creates a verifiable session with role and expiry", async () => {
    const value = await createSessionValue({ role: "platform_admin", secret, ttlSeconds: 3600 });
    const parsed = await verifySessionValue(value, secret);
    expect(parsed).toEqual(
      expect.objectContaining({ role: "platform_admin", exp: expect.any(Number) })
    );
    expect(parsed!.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("rejects tampered or empty session values", async () => {
    const value = await createSessionValue({ role: "platform_admin", secret, ttlSeconds: 3600 });
    expect(await verifySessionValue(value + "x", secret)).toBeNull();
    expect(await verifySessionValue("", secret)).toBeNull();
    expect(await verifySessionValue(value, "other-secret-xxxxxxxx")).toBeNull();
  });

  it("reads the session cookie from a Request", async () => {
    vi.stubEnv("CLM_BFF_SESSION_SECRET", secret);
    const value = await createSessionValue({ role: "platform_admin", secret, ttlSeconds: 60 });
    const req = new Request("http://localhost/api/v1/scans", {
      headers: { Cookie: `${COOKIE_NAME}=${value}` },
    });
    const session = await sessionFromRequest(req);
    expect(session?.role).toBe("platform_admin");
    expect(parseSessionCookie(`${COOKIE_NAME}=other; ${COOKIE_NAME}=${value}`)).toBe(value);
  });
});
