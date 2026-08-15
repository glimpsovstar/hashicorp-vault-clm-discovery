import { clearSessionCookieHeader } from "@/lib/bff-session";

export async function POST(): Promise<Response> {
  return Response.json(
    { ok: true },
    {
      status: 200,
      headers: { "Set-Cookie": clearSessionCookieHeader() },
    }
  );
}
