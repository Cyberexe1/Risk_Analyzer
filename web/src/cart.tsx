import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

/**
 * Cart state, shared across the shop and the checkout page.
 *
 * Lives in localStorage rather than on the server. The cart holds no money and no
 * personal data — just product ids and quantities — so a round trip per click
 * would buy nothing. Prices are deliberately NOT stored: the checkout page reads
 * them from the catalogue, and the backend recomputes the total from its own
 * CATALOGUE when the order is placed. A cart that carried its own prices would be
 * a client-controlled amount, which is the one input a risk engine must never
 * take on trust.
 */

const KEY = 'fs_cart'

/** product_id -> quantity. */
export type CartLines = Record<string, number>

interface CartState {
  lines: CartLines
  /** Total units across all products, for the nav badge. */
  count: number
  add: (productId: string, max?: number) => void
  remove: (productId: string) => void
  setQty: (productId: string, qty: number) => void
  drop: (productId: string) => void
  clear: () => void
}

const Ctx = createContext<CartState | null>(null)

function load(): CartLines {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return {}
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    // Anything in web storage is user-editable, so treat it as untrusted input:
    // keep only positive integer quantities and clamp the per-line ceiling to the
    // same limit the backend's CartLine model enforces.
    const clean: CartLines = {}
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      const n = Math.floor(Number(v))
      if (Number.isFinite(n) && n > 0) clean[k] = Math.min(n, 10)
    }
    return clean
  } catch {
    return {}
  }
}

export function CartProvider({ children }: { children: ReactNode }) {
  const [lines, setLines] = useState<CartLines>(load)

  useEffect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(lines))
    } catch {
      // Private browsing or a full quota. The cart still works for this tab.
    }
  }, [lines])

  const add = useCallback((productId: string, max = 10) => {
    setLines((c) => {
      const next = Math.min((c[productId] ?? 0) + 1, Math.min(max, 10))
      return { ...c, [productId]: next }
    })
  }, [])

  const remove = useCallback((productId: string) => {
    setLines((c) => {
      const n = (c[productId] ?? 0) - 1
      const next = { ...c }
      if (n <= 0) delete next[productId]
      else next[productId] = n
      return next
    })
  }, [])

  const setQty = useCallback((productId: string, qty: number) => {
    setLines((c) => {
      const next = { ...c }
      const n = Math.floor(qty)
      if (!Number.isFinite(n) || n <= 0) delete next[productId]
      else next[productId] = Math.min(n, 10)
      return next
    })
  }, [])

  const drop = useCallback((productId: string) => {
    setLines((c) => {
      const next = { ...c }
      delete next[productId]
      return next
    })
  }, [])

  const clear = useCallback(() => setLines({}), [])

  const count = useMemo(
    () => Object.values(lines).reduce((a, b) => a + b, 0),
    [lines],
  )

  const value = useMemo(
    () => ({ lines, count, add, remove, setQty, drop, clear }),
    [lines, count, add, remove, setQty, drop, clear],
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useCart(): CartState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useCart must be used inside <CartProvider>')
  return v
}
