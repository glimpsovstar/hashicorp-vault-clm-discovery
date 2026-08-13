import { proxyToAPI } from "@/lib/api-proxy";

async function handle(
  request: Request,
  ctx: { params: Promise<{ path: string[] }> }
): Promise<Response> {
  const { path } = await ctx.params;
  const url = new URL(request.url);
  const apiPath = `/api/v1/${path.join("/")}${url.search}`;
  return proxyToAPI(request, { method: request.method, apiPath });
}

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
export const HEAD = handle;
