import {
  createSessionValue,
  sessionSecret,
  setSessionCookieHeader,
} from "@/lib/bff-session";
import { oidcConfigured } from "@/lib/bff-oidc";

const STATE_COOKIE = "clm_bff_oidc_state";
const VERIFIER_COOKIE = "clm_bff_oidc_verifier";
const SESSION_TTL = 60 * 60 * 12;

function cookieValue(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const [rawName, ...rest] = part.trim().split("=");
    if (rawName === name) return rest.join("=");
  }
  return null;
}

export async function GET(request: Request): Promise<Response> {
  if (!oidcConfigured()) {
    return Response.json({ error: "OIDC not configured" }, { status: 503 });
  }
  const secret = sessionSecret();
  if (!secret) {
    return Response.json({ error: "CLM_BFF_SESSION_SECRET required" }, { status: 503 });
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookie = request.headers.get("Cookie");
  const expectedState = cookieValue(cookie, STATE_COOKIE);
  const verifier = cookieValue(cookie, VERIFIER_COOKIE);
  if (!code || !state || !expectedState || state !== expectedState || !verifier) {
    return Response.json({ error: "invalid OIDC callback" }, { status: 400 });
  }

  const issuer = process.env.CLM_BFF_OIDC_ISSUER!.replace(/\/$/, "");
  const clientId = process.env.CLM_BFF_OIDC_CLIENT_ID!;
  const clientSecret = process.env.CLM_BFF_OIDC_CLIENT_SECRET!;
  const redirectUri =
    process.env.CLM_BFF_OIDC_REDIRECT_URI ||
    `${url.origin}/api/auth/oidc/callback`;

  const tokenRes = await fetch(`${issuer}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: verifier,
    }),
    cache: "no-store",
  });
  if (!tokenRes.ok) {
    return Response.json({ error: "OIDC token exchange failed" }, { status: 401 });
  }

  const value = await createSessionValue({
    role: "platform_admin",
    secret,
    ttlSeconds: SESSION_TTL,
  });
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  const headers = new Headers({ Location: "/" });
  headers.append("Set-Cookie", setSessionCookieHeader(value, SESSION_TTL));
  headers.append("Set-Cookie", `${STATE_COOKIE}=; Path=/; HttpOnly; Max-Age=0${secure}`);
  headers.append("Set-Cookie", `${VERIFIER_COOKIE}=; Path=/; HttpOnly; Max-Age=0${secure}`);
  return new Response(null, { status: 302, headers });
}
