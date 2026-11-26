import { useCallback, useEffect, useMemo, useState } from 'react'
import api, { getUseSupabase, setUseSupabase } from '../api/client.js'
import { ROUTES, useHashRoute } from '../router/hash-router.js'
import Dashboard from '../views/Dashboard.jsx'
import Scans from '../views/Scans.jsx'
import Projects from '../views/Projects.jsx'
import Clients from '../views/Clients.jsx'
import Intel from '../views/Intel.jsx'

const VIEW_BY_ROUTE = Object.freeze({
  '/dashboard': Dashboard,
  '/scans': Scans,
  '/projects': Projects,
  '/clients': Clients,
  '/intel': Intel,
})

export default function AppLayout() {
  const route = useHashRoute()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [searchError, setSearchError] = useState('')
  const [storage, setStorage] = useState('SQLite local')
  const [supabaseOn, setSupabaseOn] = useState(getUseSupabase)
  const [remoteConfigured, setRemoteConfigured] = useState(false)
  const [remoteError, setRemoteError] = useState('')
  const [viewKey, setViewKey] = useState(0)

  const View = useMemo(() => VIEW_BY_ROUTE[route] || Dashboard, [route])

  const onStorageEvent = useCallback((event) => {
    if (event?.detail?.storage) setStorage(event.detail.storage)
    if (event?.detail?.remoteError != null) setRemoteError(event.detail.remoteError)
  }, [])

  useEffect(() => {
    window.addEventListener('ghostdesk-storage-meta', onStorageEvent)
    let active = true

    api.get('/ghostdesk/config')
      .then(({ data }) => {
        if (!active) return
        const configured = Boolean(data.remoteConfigured)
        setRemoteConfigured(configured)
        setStorage(data.storageLabel || 'SQLite local')
        if (!configured && getUseSupabase()) {
          setSupabaseOn(false)
          setUseSupabase(false)
        }
      })
      .catch(() => {})

    return () => {
      active = false
      window.removeEventListener('ghostdesk-storage-meta', onStorageEvent)
    }
  }, [onStorageEvent])

  const toggleSupabase = (event) => {
    const next = event.target.checked
    setSupabaseOn(next)
    setUseSupabase(next)
    setViewKey((value) => value + 1)
  }

  const search = async () => {
    const clean = query.trim()
    if (clean.length < 2) return
    setSearchError('')
    try {
      const { data } = await api.get('/ghostdesk/search', { params: { q: clean } })
      setResults(data)
    } catch (error) {
      setSearchError(error.response?.data?.error || 'erro na busca global')
    }
  }

  return (
    <div className="layout">
      <nav className="sidebar" aria-label="Navegação do GhostDesk">
        <div className="sidebar-brand">
          <h1><span>GHOST</span>DESK</h1>
          <div className="brand-sub">
            <span className="status-dot" />
            módulo GHOSTRECON
          </div>
        </div>

        <div className="nav-section">SISTEMA</div>
        {ROUTES.map((item) => (
          <a
            key={item.path}
            href={`#${item.path}`}
            className={route === item.path ? 'router-link-active' : undefined}
            aria-current={route === item.path ? 'page' : undefined}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </a>
        ))}

        <div className="nav-section" style={{ marginTop: '.5rem' }}>STORAGE</div>
        <div className="card" style={{ marginTop: '.25rem', padding: '.65rem', borderRadius: 2 }}>
          <label className="toggle-row">
            <span className={`pill-toggle${supabaseOn ? ' is-on' : ''}${remoteConfigured ? '' : ' is-disabled'}`}>
              <input
                type="checkbox"
                checked={supabaseOn}
                disabled={!remoteConfigured}
                onChange={toggleSupabase}
              />
              <span className="pill-track" />
              <span className="pill-thumb" />
            </span>
            <span>Buscar no Supabase</span>
          </label>
          <div className="kpi-label" style={{ marginTop: '.35rem' }}>
            {supabaseOn ? 'SQLite + nuvem' : 'Só SQLite local'}
          </div>
          {remoteError ? (
            <div className="err" style={{ marginTop: '.35rem' }}>{remoteError}</div>
          ) : !remoteConfigured ? (
            <div className="kpi-label" style={{ marginTop: '.35rem' }}>Supabase não configurado</div>
          ) : null}
        </div>

        <div style={{ flex: 1 }} />
        <div className="storage-status">
          <span className="status-dot" style={{ background: 'var(--accent2)' }} />
          <span className="kpi-label">{storage}</span>
        </div>
      </nav>

      <main className="content">
        <div className="row" style={{ marginBottom: '1.25rem' }}>
          <div className="search-wrap">
            <span className="search-prefix">$&gt;</span>
            <input
              value={query}
              placeholder="busca global (clientes, projetos, scans)…"
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') void search()
              }}
            />
          </div>
          <button className="primary" type="button" onClick={() => void search()}>Buscar</button>
        </div>

        {searchError ? <p className="err" style={{ marginBottom: '1rem' }}>{searchError}</p> : null}
        {results ? (
          <div className="card" style={{ marginBottom: '1rem' }}>
            <strong>Resultados para &quot;{results.query}&quot;</strong>
            <div className="grid cols-2" style={{ marginTop: '.6rem' }}>
              {Object.entries(results.results || {}).map(([kind, items]) => (
                <div key={kind}>
                  <div className="kpi-label">{kind} ({items.length})</div>
                  {items.map((item, index) => (
                    <div key={`${kind}-${item.id || index}`} style={{ fontSize: '.85rem' }}>
                      {item.company || item.name || item.target}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        <View key={`${route}:${viewKey}`} />
      </main>
    </div>
  )
}
