import { serverAuthorization } from "@/lib/api-proxy";

// resolveApiBaseUrl: server components call the Go API directly; the browser
// uses the same-origin BFF (empty base → /api/v1/...). Never put tokens in
// NEXT_PUBLIC_*.
export function resolveApiBaseUrl(isBrowser: boolean): string {
  if (!isBrowser) {
    return (
      process.env.API_INTERNAL_URL ||
      process.env.NEXT_PUBLIC_API_URL ||
      "http://localhost:8080"
    );
  }
  return "";
}

// apiRequestHeaders attaches CLM_API_TOKEN only on the server. Browser fetches
// go through the BFF, which adds Authorization from server-only env.
export function apiRequestHeaders(isBrowser: boolean): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (!isBrowser) {
    const auth = serverAuthorization(null);
    if (auth) {
      headers.Authorization = auth;
    }
  }
  return headers;
}
