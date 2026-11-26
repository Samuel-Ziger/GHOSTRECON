import { useEffect, useState } from 'react'

export const ROUTES = Object.freeze([
  { path: '/dashboard', label: 'Dashboard', icon: '◈' },
  { path: '/scans', label: 'Scans', icon: '⊕' },
  { path: '/projects', label: 'Projetos', icon: '⊞' },
  { path: '/clients', label: 'Clientes', icon: '⊙' },
  { path: '/intel', label: 'Intel', icon: '◎' },
])

const ROUTE_SET = new Set(ROUTES.map((route) => route.path))

export function normalizeHashRoute(hash = '') {
  const raw = String(hash).replace(/^#/, '').trim()
  const path = raw.startsWith('/') ? raw : `/${raw}`
  return ROUTE_SET.has(path) ? path : '/dashboard'
}

export function useHashRoute() {
  const [route, setRoute] = useState(() => normalizeHashRoute(window.location.hash))

  useEffect(() => {
    const sync = () => {
      const next = normalizeHashRoute(window.location.hash)
      setRoute(next)
      if (window.location.hash !== `#${next}`) {
        window.history.replaceState(null, '', `#${next}`)
      }
    }

    sync()
    window.addEventListener('hashchange', sync)
    return () => window.removeEventListener('hashchange', sync)
  }, [])

  return route
}
