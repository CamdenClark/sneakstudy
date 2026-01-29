import { Hono } from 'hono'
import { renderer } from './renderer'
import { authRoutes, authMiddleware, requireAuth } from './auth'

type Env = {
  Bindings: {
    WORKOS_API_KEY: string
    WORKOS_CLIENT_ID: string
    WORKOS_COOKIE_PASSWORD: string
    WORKOS_REDIRECT_URI?: string
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
      <a href="/auth/logout">Sign out</a>
    </div>
  )
})

export default app
