const CONNECTIONS_PATH = "/api/v1/settings/connections";

function goApiBaseUrl(): string {
  return process.env.API_INTERNAL_URL || "http://localhost:8080";
}

function serverAuthorization(incoming: string | null): string | undefined {
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

type ProxyOptions = {
  method: string;
  suffix?: string;
};

// proxySettings forwards Connections requests to the Go API using server-only
// env (API_INTERNAL_URL, CLM_API_TOKEN). Never read NEXT_PUBLIC_* secrets.
export async function proxySettings(request: Request, opts: ProxyOptions): Promise<Response> {
  const url = `${goApiBaseUrl()}${CONNECTIONS_PATH}${opts.suffix ?? ""}`;
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
  return new Response(res.body, { status: res.status, headers: out });
}
