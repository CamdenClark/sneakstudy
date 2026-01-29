import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { createMiddleware } from 'hono/factory'
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

const PKCE_VERIFIER_COOKIE = 'openrouter_pkce_verifier'

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function getUserDO(env: Env['Bindings'], userId: string) {
  const id = env.USER_DO.idFromName(userId)
  return env.USER_DO.get(id)
}

export const requireOpenRouter = createMiddleware<Env>(async (c, next) => {
  const user = c.get('user')

  if (!user) {
    return next()
  }

  const userDO = getUserDO(c.env, user.id)
  const hasToken = await userDO.hasToken()

  if (!hasToken && !c.req.path.startsWith('/onboarding') && !c.req.path.startsWith('/openrouter')) {
    return c.redirect('/onboarding')
  }

  return next()
})

export const openrouterRoutes = new Hono<Env>()

openrouterRoutes.get('/connect', async (c) => {
  const user = c.get('user')
  if (!user) {
    return c.redirect('/auth/login')
  }

  const codeVerifier = generateCodeVerifier()
  const codeChallenge = await generateCodeChallenge(codeVerifier)

  const url = new URL(c.req.url)
  const callbackUrl = `${url.origin}/openrouter/callback`

  setCookie(c, PKCE_VERIFIER_COOKIE, codeVerifier, {
    path: '/',
    httpOnly: true,
    secure: url.hostname !== 'localhost' && url.hostname !== '127.0.0.1',
    sameSite: 'Lax',
    maxAge: 60 * 10, // 10 minutes
  })

  const authUrl = new URL('https://openrouter.ai/auth')
  authUrl.searchParams.set('callback_url', callbackUrl)
  authUrl.searchParams.set('code_challenge', codeChallenge)
  authUrl.searchParams.set('code_challenge_method', 'S256')

  return c.redirect(authUrl.toString())
})

openrouterRoutes.get('/callback', async (c) => {
  const user = c.get('user')
  if (!user) {
    return c.redirect('/auth/login')
  }

  const code = c.req.query('code')
  if (!code) {
    return c.text('Missing authorization code', 400)
  }

  const codeVerifier = getCookie(c, PKCE_VERIFIER_COOKIE)
  if (!codeVerifier) {
    return c.text('Missing PKCE verifier - please try again', 400)
  }

  deleteCookie(c, PKCE_VERIFIER_COOKIE, { path: '/' })

  try {
    const response = await fetch('https://openrouter.ai/api/v1/auth/keys', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code,
        code_verifier: codeVerifier,
        code_challenge_method: 'S256',
      }),
    })

    if (!response.ok) {
      const error = await response.text()
      console.error('OpenRouter token exchange failed:', error)
      return c.text('Failed to exchange code for token', 500)
    }

    const data = await response.json() as { key: string }

    const userDO = getUserDO(c.env, user.id)
    await userDO.setToken(data.key)

    return c.redirect('/')
  } catch (error) {
    console.error('OpenRouter callback error:', error)
    return c.text(`OpenRouter authentication failed: ${error}`, 500)
  }
})

openrouterRoutes.get('/disconnect', async (c) => {
  const user = c.get('user')
  if (!user) {
    return c.redirect('/auth/login')
  }

  const userDO = getUserDO(c.env, user.id)
  await userDO.deleteToken()

  return c.redirect('/onboarding')
})
