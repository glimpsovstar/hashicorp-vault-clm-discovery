// Optional OIDC helpers for BFF session establishment (Authorization Code + PKCE).

export type OidcAuthorizeParams = {
  issuer: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
};

export function oidcConfigured(): boolean {
  return Boolean(
    process.env.CLM_BFF_OIDC_ISSUER &&
      process.env.CLM_BFF_OIDC_CLIENT_ID &&
      process.env.CLM_BFF_OIDC_CLIENT_SECRET
  );
}

export function buildOidcAuthorizeUrl(p: OidcAuthorizeParams): string {
  const base = p.issuer.replace(/\/$/, "");
  const u = new URL(`${base}/authorize`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", p.clientId);
  u.searchParams.set("redirect_uri", p.redirectUri);
  u.searchParams.set("scope", "openid profile");
  u.searchParams.set("state", p.state);
  u.searchParams.set("code_challenge", p.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function randomToken(bytes = 32): Promise<string> {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return b64url(buf);
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}
