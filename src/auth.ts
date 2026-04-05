import { createMiddleware } from "hono/factory";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { WorkOS } from "@workos-inc/node";
import { createRemoteJWKSet, jwtVerify } from "jose";

type Env = {
  Bindings: {
    WORKOS_API_KEY: string;
    WORKOS_CLIENT_ID: string;
    WORKOS_REDIRECT_URI: string;
  };
  Variables: {
    userId: string;
    email: string;
  };
};

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export function getJWKS(clientId: string) {
  if (!jwksCache.has(clientId)) {
    jwksCache.set(
      clientId,
      createRemoteJWKSet(
        new URL(`https://api.workos.com/sso/jwks/${clientId}`)
      )
    );
  }
  return jwksCache.get(clientId)!;
}

export const authMiddleware = createMiddleware<Env>(async (c, next) => {
  const accessToken = getCookie(c, "access_token");

  if (!accessToken) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  try {
    const JWKS = getJWKS(c.env.WORKOS_CLIENT_ID);
    const { payload } = await jwtVerify(accessToken, JWKS);
    c.set("userId", payload.sub as string);
    c.set("email", (payload as any).email as string);
  } catch {
    // Try refreshing
    const refreshToken = getCookie(c, "refresh_token");
    if (!refreshToken) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    try {
      const workos = new WorkOS(c.env.WORKOS_API_KEY);
      const result = await workos.userManagement.authenticateWithRefreshToken({
        clientId: c.env.WORKOS_CLIENT_ID,
        refreshToken,
      });

      setCookie(c, "access_token", result.accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
      });
      setCookie(c, "refresh_token", result.refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
      });

      const JWKS = getJWKS(c.env.WORKOS_CLIENT_ID);
      const { payload } = await jwtVerify(result.accessToken, JWKS);
      c.set("userId", payload.sub as string);
      c.set("email", (payload as any).email as string);
    } catch {
      deleteCookie(c, "access_token");
      deleteCookie(c, "refresh_token");
      return c.json({ error: "Unauthorized" }, 401);
    }
  }

  await next();
});
