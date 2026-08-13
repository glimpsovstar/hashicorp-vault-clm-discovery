import { proxySettings } from "@/lib/settings-proxy";

export async function POST(request: Request) {
  return proxySettings(request, { method: "POST", suffix: "/test" });
}
