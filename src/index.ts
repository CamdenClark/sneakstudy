import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { WorkOS } from "@workos-inc/node";
import { authMiddleware } from "./auth";

type Env = {
  Bindings: {
    WORKOS_API_KEY: string;
    WORKOS_CLIENT_ID: string;
    WORKOS_REDIRECT_URI: string;
  };
  Variables: {
    userId: string;
  };
};

const app = new Hono<Env>();

app.get("/auth/login", (c) => {
  const workos = new WorkOS(c.env.WORKOS_API_KEY);
  const url = workos.userManagement.getAuthorizationUrl({
    clientId: c.env.WORKOS_CLIENT_ID,
    redirectUri: c.env.WORKOS_REDIRECT_URI,
    provider: "authkit",
  });
  return c.redirect(url);
});

app.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  if (!code) {
    return c.json({ error: "Missing code" }, 400);
  }

  const workos = new WorkOS(c.env.WORKOS_API_KEY);
  const { accessToken, refreshToken } =
    await workos.userManagement.authenticateWithCode({
      clientId: c.env.WORKOS_CLIENT_ID,
      code,
    });

  setCookie(c, "access_token", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
  });
  setCookie(c, "refresh_token", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
  });

  return c.redirect("/");
});

app.get("/auth/logout", (c) => {
  const workos = new WorkOS(c.env.WORKOS_API_KEY);
  const accessToken = getCookie(c, "access_token");

  return c.redirect(
    workos.userManagement.getLogoutUrl({ sessionId: accessToken ?? "" })
  );
});

// Protected routes
app.use("/api/*", authMiddleware);

app.get("/api/me", (c) => {
  return c.json({ userId: c.get("userId") });
});

app.get("/", (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SneakStudy</title>
</head>
<body>
  <h1>SneakStudy</h1>
  <a href="/auth/login">Log in</a>
</body>
</html>`);
});

export default app;
