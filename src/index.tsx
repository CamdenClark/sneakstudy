import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { WorkOS } from "@workos-inc/node";
import { authMiddleware, getSessionFromCookie, SESSION_COOKIE } from "./auth";

type Env = {
  Bindings: {
    WORKOS_API_KEY: string;
    WORKOS_CLIENT_ID: string;
    WORKOS_REDIRECT_URI?: string;
    WORKOS_COOKIE_PASSWORD: string;
  };
  Variables: {
    userId: string;
    email: string;
  };
};

const app = new Hono<Env>();

function getRedirectUri(c: { env: Env["Bindings"]; req: { url: string } }) {
  return c.env.WORKOS_REDIRECT_URI ?? new URL("/auth/callback", c.req.url).toString();
}

app.get("/auth/login", (c) => {
  const workos = new WorkOS(c.env.WORKOS_API_KEY, { clientId: c.env.WORKOS_CLIENT_ID });
  const url = workos.userManagement.getAuthorizationUrl({
    clientId: c.env.WORKOS_CLIENT_ID,
    redirectUri: getRedirectUri(c),
    provider: "authkit",
  });
  return c.redirect(url);
});

app.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  if (!code) {
    return c.json({ error: "Missing code" }, 400);
  }

  const workos = new WorkOS(c.env.WORKOS_API_KEY, { clientId: c.env.WORKOS_CLIENT_ID });
  const { sealedSession } =
    await workos.userManagement.authenticateWithCode({
      clientId: c.env.WORKOS_CLIENT_ID,
      code,
      session: {
        sealSession: true,
        cookiePassword: c.env.WORKOS_COOKIE_PASSWORD,
      },
    });

  setCookie(c, SESSION_COOKIE, sealedSession!, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
  });

  return c.redirect("/");
});

app.get("/auth/logout", async (c) => {
  const workos = new WorkOS(c.env.WORKOS_API_KEY, { clientId: c.env.WORKOS_CLIENT_ID });
  const sessionData = getCookie(c, SESSION_COOKIE);

  if (sessionData) {
    const session = workos.userManagement.loadSealedSession({
      sessionData,
      cookiePassword: c.env.WORKOS_COOKIE_PASSWORD,
    });
    const url = await session.getLogoutUrl();
    deleteCookie(c, SESSION_COOKIE);
    return c.redirect(url);
  }

  deleteCookie(c, SESSION_COOKIE);
  return c.redirect("/");
});

// Protected routes
app.use("/api/*", authMiddleware);

app.get("/api/me", (c) => {
  return c.json({ userId: c.get("userId"), email: c.get("email") });
});

app.get("/", async (c) => {
  const sessionData = getCookie(c, SESSION_COOKIE);
  const session = await getSessionFromCookie({
    env: c.env,
    sessionData,
  });

  if (session?.sealedSession) {
    setCookie(c, SESSION_COOKIE, session.sealedSession, {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
    });
  }

  return c.html(
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>SneakStudy</title>
      </head>
      <body>
        <h1>SneakStudy</h1>
        {session ? (
          <p>
            Logged in as {session.user.email} — <a href="/auth/logout">Log out</a>
          </p>
        ) : (
          <a href="/auth/login">Log in</a>
        )}
      </body>
    </html>
  );
});

export default app;
