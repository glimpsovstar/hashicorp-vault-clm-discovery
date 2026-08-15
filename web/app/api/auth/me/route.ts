import { sessionFromRequest } from "@/lib/bff-session";

export async function GET(request: Request): Promise<Response> {
  const session = await sessionFromRequest(request);
  if (!session) {
    return Response.json({ authenticated: false }, { status: 200 });
  }
  return Response.json({ authenticated: true, role: session.role }, { status: 200 });
}
