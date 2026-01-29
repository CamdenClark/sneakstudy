import { Hono } from 'hono'
import { renderer } from './renderer'
import { authRoutes, authMiddleware, requireAuth } from './auth'
import { openrouterRoutes, requireOpenRouter } from './openrouter'
import { UserDurableObject } from './db/user-do'

export { UserDurableObject }

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
  }
}

const app = new Hono<Env>()

app.use(renderer)
app.use(authMiddleware)

app.route('/auth', authRoutes)
app.route('/openrouter', openrouterRoutes)

app.get('/onboarding', requireAuth, (c) => {
  return c.render(
    <div>
      <h1>Connect OpenRouter</h1>
      <p>To use SneakStudy, you need to connect your OpenRouter account.</p>
      <a href="/openrouter/connect">Connect OpenRouter</a>
    </div>
  )
})

app.use(requireOpenRouter)

app.get('/', (c) => {
  const user = c.get('user')

  if (!user) {
    return c.render(
      <div>
        <h1>Welcome to SneakStudy</h1>
        <a href="/auth/login">Sign in</a>
      </div>
    )
  }

  return c.render(
    <div>
      <h1>Hello, {user.firstName || user.email}!</h1>
      <p>OpenRouter connected!</p>
      <a href="/openrouter/disconnect">Disconnect OpenRouter</a>
      {' | '}
      <a href="/auth/logout">Sign out</a>
    </div>
  )
})

export default app
