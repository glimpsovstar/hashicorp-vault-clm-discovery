import { proxyToAPI } from "@/lib/api-proxy";

const CONNECTIONS_PATH = "/api/v1/settings/connections";

type ProxyOptions = {
  method: string;
  suffix?: string;
};

// proxySettings forwards Connections requests to the Go API using server-only
// env (API_INTERNAL_URL, CLM_API_TOKEN). Never read NEXT_PUBLIC_* secrets.
export async function proxySettings(request: Request, opts: ProxyOptions): Promise<Response> {
  return proxyToAPI(request, {
    method: opts.method,
    apiPath: `${CONNECTIONS_PATH}${opts.suffix ?? ""}`,
  });
}
