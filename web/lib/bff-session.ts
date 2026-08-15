// Signed httpOnly BFF session. Demo/OIDC login sets the cookie; proxyToAPI
// requires a valid session before attaching CLM_API_TOKEN.

export const COOKIE_NAME = "clm_bff_session";

export type BffSession = {
  role: string;
  exp: number;
};

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacSign(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64urlEncode(new Uint8Array(sig));
}

async function hmacVerify(secret: string, data: string, sig: string): Promise<boolean> {
  const expected = await hmacSign(secret, data);
  if (expected.length !== sig.length) return false;
  let ok = 0;
  for (let i = 0; i < expected.length; i++) {
    ok |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  }
  return ok === 0;
}

export async function createSessionValue(opts: {
  role: string;
  secret: string;
  ttlSeconds: number;
}): Promise<string> {
  const payload: BffSession = {
    role: opts.role,
    exp: Math.floor(Date.now() / 1000) + opts.ttlSeconds,
  };
  const body = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await hmacSign(opts.secret, body);
  return `${body}.${sig}`;
}

export async function verifySessionValue(
  value: string,
  secret: string
): Promise<BffSession | null> {
  if (!value || !secret) return null;
  const parts = value.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  if (!(await hmacVerify(secret, body, sig))) return null;
  try {
    const json = new TextDecoder().decode(b64urlDecode(body));
    const parsed = JSON.parse(json) as BffSession;
    if (!parsed?.role || typeof parsed.exp !== "number") return null;
    if (parsed.exp < Math.floor(Date.now() / 1000)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function parseSessionCookie(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  let found: string | null = null;
  for (const part of parts) {
    const [rawName, ...rest] = part.trim().split("=");
    if (rawName === COOKIE_NAME) {
      found = rest.join("=");
    }
  }
  return found;
}

export function sessionSecret(): string | undefined {
  const s = process.env.CLM_BFF_SESSION_SECRET;
  return s && s.length >= 16 ? s : undefined;
}

export function insecureNoSession(): boolean {
  return process.env.CLM_BFF_INSECURE_NO_SESSION === "true";
}

export async function sessionFromRequest(request: Request): Promise<BffSession | null> {
  const secret = sessionSecret();
  if (!secret) return null;
  const raw = parseSessionCookie(request.headers.get("Cookie"));
  if (!raw) return null;
  return verifySessionValue(raw, secret);
}

export function setSessionCookieHeader(value: string, maxAgeSeconds: number): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`;
}

export function clearSessionCookieHeader(): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}
