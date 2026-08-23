import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { authApi, setAccessToken, type PublicUser } from './api'

interface AuthState {
  user: PublicUser | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

/**
 * The access token is held in a module variable inside api.ts, never in
 * localStorage or sessionStorage. Anything in web storage is readable by any
 * script that gets injected, so an XSS becomes a permanent account takeover.
 * In memory, a token dies with the tab.
 *
 * The refresh token is an httpOnly cookie, so JavaScript cannot read it at all.
 * On mount we try to exchange it for a fresh access token — that is what keeps a
 * page reload from logging you out without putting a long-lived credential
 * anywhere a script can reach.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<PublicUser | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const r = await authApi.refresh()
        if (!cancelled) {
          setAccessToken(r.access_token)
          setUser(r.user)
        }
      } catch {
        // No session, or the backend is down. Either way, anonymous.
        if (!cancelled) setAccessToken(null)
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    const r = await authApi.login(email, password)
    setAccessToken(r.access_token)
    setUser(r.user)
  }, [])

  const register = useCallback(async (email: string, password: string) => {
    const r = await authApi.register(email, password)
    setAccessToken(r.access_token)
    setUser(r.user)
  }, [])

  const logout = useCallback(async () => {
    try {
      await authApi.logout()
    } finally {
      setAccessToken(null)
      setUser(null)
    }
  }, [])

  const value = useMemo(
    () => ({ user, loading, login, register, logout }),
    [user, loading, login, register, logout],
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuth must be used inside <AuthProvider>')
  return v
}

/** Client-side mirror of the backend's password policy, for immediate feedback.
 *  The backend re-checks everything — this is UX, not enforcement. */
export function passwordProblem(pw: string): string | null {
  if (pw.length < 10) return 'At least 10 characters.'
  if (/^\d+$/.test(pw)) return 'Cannot be only digits.'
  const common = [
    'password', 'password1', 'password12', 'password123', 'passw0rd123',
    '1234567890', '12345678910', 'qwertyuiop', 'letmein123', 'iloveyou1',
    'admin12345', 'welcome123', 'abc12345678', 'changeme123', 'fraudshield',
  ]
  if (common.includes(pw.toLowerCase())) return 'Too common. Pick something less predictable.'
  return null
}

export function passwordStrength(pw: string): { score: 0 | 1 | 2 | 3; label: string } {
  if (!pw) return { score: 0, label: '' }
  let bits = 0
  if (pw.length >= 10) bits++
  if (pw.length >= 16) bits++
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) bits++
  if (/\d/.test(pw)) bits++
  if (/[^A-Za-z0-9]/.test(pw)) bits++
  if (passwordProblem(pw)) return { score: 0, label: 'Too weak' }
  if (bits <= 2) return { score: 1, label: 'Weak' }
  if (bits === 3) return { score: 2, label: 'Reasonable' }
  return { score: 3, label: 'Strong' }
}
