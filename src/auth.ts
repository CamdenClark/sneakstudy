import { createMiddleware } from "hono/factory";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { WorkOS } from "@workos-inc/node";

type Env = {
  Bindings: {
    WORKOS_API_KEY: string;
    WORKOS_CLIENT_ID: string;
    WORKOS_REDIRECT_URI: string;
    WORKOS_COOKIE_PASSWORD: string;
  };
  Variables: {
    userId: string;
    email: string;
  };
};

const SESSION_COOKIE = "wos-session";

export async function getSessionFromCookie(c: {
  env: Env["Bindings"];
  sessionData: string | undefined;
}) {
  if (!c.sessionData) return null;

  const workos = new WorkOS(c.env.WORKOS_API_KEY, { clientId: c.env.WORKOS_CLIENT_ID });
  const session = workos.userManagement.loadSealedSession({
    sessionData: c.sessionData,
    cookiePassword: c.env.WORKOS_COOKIE_PASSWORD,
  });

  const result = await session.authenticate();
  if (result.authenticated) {
    return { user: result.user, sessionId: result.sessionId };
  }

  // Try refresh
  const refreshResult = await session.refresh();
  if (refreshResult.authenticated) {
    return {
      user: refreshResult.user,
      sessionId: refreshResult.sessionId,
      sealedSession: refreshResult.sealedSession,
    };
  }

  return null;
}

export { SESSION_COOKIE };

export const authMiddleware = createMiddleware<Env>(async (c, next) => {
  const sessionData = getCookie(c, SESSION_COOKIE);

  const session = await getSessionFromCookie({
    env: c.env,
    sessionData,
  });

  if (!session) {
    deleteCookie(c, SESSION_COOKIE);
    return c.json({ error: "Unauthorized" }, 401);
  }

  if (session.sealedSession) {
    setCookie(c, SESSION_COOKIE, session.sealedSession, {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
    });
  }

  c.set("userId", session.user.id);
  c.set("email", session.user.email);

  await next();
});
