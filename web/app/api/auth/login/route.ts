import {
  createSessionValue,
  sessionSecret,
  setSessionCookieHeader,
} from "@/lib/bff-session";

const SESSION_TTL = 60 * 60 * 12; // 12h

export async function POST(request: Request): Promise<Response> {
  const secret = sessionSecret();
  const demoPassword = process.env.CLM_BFF_DEMO_PASSWORD;
  if (!secret || !demoPassword) {
    return Response.json(
      { error: "BFF session login not configured (CLM_BFF_SESSION_SECRET + CLM_BFF_DEMO_PASSWORD)" },
      { status: 503 }
    );
  }

  let body: { password?: string };
  try {
    body = (await request.json()) as { password?: string };
  } catch {
    return Response.json({ error: "invalid request body" }, { status: 400 });
  }
  if (!body.password || body.password !== demoPassword) {
    return Response.json({ error: "authentication required" }, { status: 401 });
  }

  const value = await createSessionValue({
    role: "platform_admin",
    secret,
    ttlSeconds: SESSION_TTL,
  });
  return Response.json(
    { role: "platform_admin" },
    {
      status: 200,
      headers: { "Set-Cookie": setSessionCookieHeader(value, SESSION_TTL) },
    }
  );
}
