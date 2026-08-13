function goApiBaseUrl(): string {
  return process.env.API_INTERNAL_URL || "http://localhost:8080";
}

// serverAuthorization prefers an incoming Authorization header, else CLM_API_TOKEN.
// Never read NEXT_PUBLIC_* secrets.
export function serverAuthorization(incoming: string | null): string | undefined {
  if (incoming) {
    return incoming;
  }
  const token = process.env.CLM_API_TOKEN;
  if (!token) {
    return undefined;
  }
  if (token.startsWith("Bearer ") || token.startsWith("Token ")) {
    return token;
  }
  return `Bearer ${token}`;
}

function isAAPInventory(apiPath: string): boolean {
  const path = apiPath.split("?")[0];
  return path === "/api/v1/inventory" || path.startsWith("/api/v1/inventory/");
}

type ProxyToAPIOptions = {
  method: string;
  apiPath: string;
};

// proxyToAPI forwards a same-origin BFF request to the Go API using server-only
// env (API_INTERNAL_URL, CLM_API_TOKEN). AAP GET /inventory is not proxied —
// that endpoint is a service identity, not a dashboard page.
export async function proxyToAPI(request: Request, opts: ProxyToAPIOptions): Promise<Response> {
  if (isAAPInventory(opts.apiPath)) {
    return Response.json({ error: "not found" }, { status: 404 });
  }

  const url = `${goApiBaseUrl()}${opts.apiPath}`;
  const headers: Record<string, string> = {};
  const contentType = request.headers.get("Content-Type");
  if (contentType) {
    headers["Content-Type"] = contentType;
  } else if (opts.method !== "GET" && opts.method !== "HEAD") {
    headers["Content-Type"] = "application/json";
  }
  const auth = serverAuthorization(request.headers.get("Authorization"));
  if (auth) {
    headers.Authorization = auth;
  }

  const init: RequestInit = {
    method: opts.method,
    headers,
    cache: "no-store",
  };
  if (opts.method !== "GET" && opts.method !== "HEAD") {
    init.body = await request.text();
  }

  const res = await fetch(url, init);
  const out = new Headers();
  const ct = res.headers.get("Content-Type");
  if (ct) {
    out.set("Content-Type", ct);
  }
  const disposition = res.headers.get("Content-Disposition");
  if (disposition) {
    out.set("Content-Disposition", disposition);
  }
  return new Response(res.body, { status: res.status, headers: out });
}
