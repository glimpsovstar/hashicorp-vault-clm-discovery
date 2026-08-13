import { proxySettings } from "@/lib/settings-proxy";

export async function GET(request: Request) {
  return proxySettings(request, { method: "GET" });
}

export async function PUT(request: Request) {
  return proxySettings(request, { method: "PUT" });
}

export async function PATCH(request: Request) {
  return proxySettings(request, { method: "PATCH" });
}
