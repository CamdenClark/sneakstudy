import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { createMiddleware } from 'hono/factory'
import { WorkOS } from '@workos-inc/node'

import type { UserDurableObject } from './db/user-do'

type Env = {
  Bindings: {
    WORKOS_API_KEY: string
    WORKOS_CLIENT_ID: string
    WORKOS_COOKIE_PASSWORD: string
    WORKOS_REDIRECT_URI?: string
    USER_DO: DurableObjectNamespace<UserDurableObject>
  }
  Variables: {
    user: {
      id: string
      email: string
      firstName: string | null
      lastName: string | null
    } | null
    sessionId: string | null
  }
}

const SESSION_COOKIE = 'wos_session'

function getWorkOS(apiKey: string, clientId: string) {
  return new WorkOS(apiKey, { clientId })
}

function getRedirectUri(c: { env: Env['Bindings']; req: { url: string } }) {
  if (c.env.WORKOS_REDIRECT_URI) {
    return c.env.WORKOS_REDIRECT_URI
  }
  const url = new URL(c.req.url)
  return `${url.origin}/auth/callback`
}

function shouldUseSecureCookie(url: string): boolean {
  const parsed = new URL(url)
  // Don't require secure cookies on localhost for development
  return parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1'
}

export const authMiddleware = createMiddleware<Env>(async (c, next) => {
  const sessionToken = getCookie(c, SESSION_COOKIE)

  if (!sessionToken) {
    c.set('user', null)
    c.set('sessionId', null)
    return next()
  }

  try {
    const workos = getWorkOS(c.env.WORKOS_API_KEY, c.env.WORKOS_CLIENT_ID)
    const result = await workos.userManagement.authenticateWithSessionCookie({
      sessionData: sessionToken,
      cookiePassword: c.env.WORKOS_COOKIE_PASSWORD,
    })

    if (!result.authenticated) {
      deleteCookie(c, SESSION_COOKIE, { path: '/' })
      c.set('user', null)
      c.set('sessionId', null)
      return next()
    }

    c.set('user', {
      id: result.user.id,
      email: result.user.email,
      firstName: result.user.firstName,
      lastName: result.user.lastName,
    })
    c.set('sessionId', result.sessionId)
  } catch (error) {
    console.error('Session validation error:', error)
    deleteCookie(c, SESSION_COOKIE, { path: '/' })
    c.set('user', null)
    c.set('sessionId', null)
  }

  return next()
})

export const requireAuth = createMiddleware<Env>(async (c, next) => {
  const user = c.get('user')

  if (!user) {
    return c.redirect('/auth/login')
  }

  return next()
})

export const authRoutes = new Hono<Env>()

authRoutes.get('/login', async (c) => {
  const workos = getWorkOS(c.env.WORKOS_API_KEY, c.env.WORKOS_CLIENT_ID)
  const redirectUri = getRedirectUri(c)

  const authorizationUrl = workos.userManagement.getAuthorizationUrl({
    provider: 'authkit',
    clientId: c.env.WORKOS_CLIENT_ID,
    redirectUri,
  })

  return c.redirect(authorizationUrl)
})

authRoutes.get('/callback', async (c) => {
  const code = c.req.query('code')

  if (!code) {
    return c.text('Missing authorization code', 400)
  }

  try {
    const workos = getWorkOS(c.env.WORKOS_API_KEY, c.env.WORKOS_CLIENT_ID)

    const { sealedSession } = await workos.userManagement.authenticateWithCode({
      clientId: c.env.WORKOS_CLIENT_ID,
      code,
      session: {
        sealSession: true,
        cookiePassword: c.env.WORKOS_COOKIE_PASSWORD,
      },
    })

    if (sealedSession) {
      const secure = shouldUseSecureCookie(c.req.url)
      setCookie(c, SESSION_COOKIE, sealedSession, {
        path: '/',
        httpOnly: true,
        secure,
        sameSite: 'Lax',
        maxAge: 60 * 60 * 24 * 7, // 7 days
      })
    }

    return c.redirect('/')
  } catch (error) {
    console.error('Auth callback error:', error)
    return c.text(`Authentication failed: ${error}`, 500)
  }
})

authRoutes.get('/logout', async (c) => {
  const sessionId = c.get('sessionId')

  deleteCookie(c, SESSION_COOKIE, { path: '/' })

  if (sessionId) {
    try {
      const workos = getWorkOS(c.env.WORKOS_API_KEY, c.env.WORKOS_CLIENT_ID)
      const logoutUrl = workos.userManagement.getLogoutUrl({ sessionId })
      return c.redirect(logoutUrl)
    } catch (error) {
      console.error('Logout error:', error)
    }
  }

  return c.redirect('/')
})
