import {
  buildOidcAuthorizeUrl,
  oidcConfigured,
  pkceChallenge,
  randomToken,
} from "@/lib/bff-oidc";

const STATE_COOKIE = "clm_bff_oidc_state";
const VERIFIER_COOKIE = "clm_bff_oidc_verifier";

export async function GET(request: Request): Promise<Response> {
  if (!oidcConfigured()) {
    return Response.json({ error: "OIDC not configured" }, { status: 503 });
  }
  const issuer = process.env.CLM_BFF_OIDC_ISSUER!;
  const clientId = process.env.CLM_BFF_OIDC_CLIENT_ID!;
  const url = new URL(request.url);
  const redirectUri =
    process.env.CLM_BFF_OIDC_REDIRECT_URI ||
    `${url.origin}/api/auth/oidc/callback`;

  const state = await randomToken(16);
  const verifier = await randomToken(32);
  const challenge = await pkceChallenge(verifier);
  const authorize = buildOidcAuthorizeUrl({
    issuer,
    clientId,
    redirectUri,
    state,
    codeChallenge: challenge,
  });

  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  const headers = new Headers({ Location: authorize });
  headers.append(
    "Set-Cookie",
    `${STATE_COOKIE}=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secure}`
  );
  headers.append(
    "Set-Cookie",
    `${VERIFIER_COOKIE}=${verifier}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secure}`
  );
  return new Response(null, { status: 302, headers });
}
