import { useEffect, useMemo, useState } from 'react'
import api from '../api/client.js'
import { badgeClass, formatDate, severityColor } from '../lib/formatters.js'

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    api.get('/ghostdesk/overview')
      .then(({ data: overview }) => {
        if (!active) return
        setData(overview)
        window.dispatchEvent(new CustomEvent('ghostdesk-storage-meta', {
          detail: { storage: overview.storage, remoteError: overview.remoteError || '' },
        }))
      })
      .catch((requestError) => {
        if (active) setError(requestError.response?.data?.error || 'erro ao carregar dashboard')
      })
    return () => { active = false }
  }, [])

  const maxSeverity = useMemo(
    () => Math.max(...Object.values(data?.findingsBySeverity || {}), 1),
    [data],
  )

  if (error) {
    return <p className="err">{error}</p>
  }

  return (
    <>
      <h2>Dashboard</h2>
      {!data ? (
        <div className="loading-wrap"><span className="spinner" /></div>
      ) : (
        <>
          <div className="grid cols-4">
            <KpiCard icon="⬡" value={data.totals.scans} label="Scans (runs)" />
            <KpiCard icon="◎" value={data.totals.targets} label="Alvos únicos" />
            <KpiCard icon="⊞" value={data.totals.projects} label="Projetos" />
            <KpiCard icon="⊙" value={data.totals.clients} label="Clientes" />
          </div>

          <div className="grid cols-2" style={{ marginTop: '1rem' }}>
            <div className="card">
              <h3>Findings por prioridade</h3>
              {Object.entries(data.findingsBySeverity || {}).map(([priority, count]) => (
                <div key={priority} className="sev-row">
                  <span className={`badge ${badgeClass(priority)}`} style={{ minWidth: '5rem', textAlign: 'center' }}>
                    {priority}
                  </span>
                  <div className="sev-bar-wrap">
                    <div className="sev-bar">
                      <div
                        className="sev-bar-fill"
                        style={{ width: `${Math.round((count / maxSeverity) * 100)}%`, background: severityColor(priority) }}
                      />
                    </div>
                    <strong className="severity-count">{count}</strong>
                  </div>
                </div>
              ))}
              {!Object.keys(data.findingsBySeverity || {}).length ? (
                <div className="kpi-label" style={{ padding: '.5rem 0' }}>Nenhum finding ainda.</div>
              ) : null}
            </div>

            <div className="card">
              <h3>Armazenamento</h3>
              <div className="kpi">{data.storage}</div>
              {data.sources ? (
                <div className="source-badges">
                  {Object.entries(data.sources).map(([source, count]) => (
                    <span key={source} className="badge badge-muted">
                      {source}&nbsp;<strong style={{ color: 'var(--text)' }}>{count}</strong>
                    </span>
                  ))}
                </div>
              ) : null}
              <div className="kpi-label" style={{ marginTop: '.6rem' }}>
                SQLite local + escopo + Supabase quando online
              </div>
            </div>
          </div>

          <div className="card" style={{ marginTop: '1rem' }}>
            <h3>Scans recentes</h3>
            <table>
              <thead><tr><th>Origem</th><th>Alvo</th><th>Data</th></tr></thead>
              <tbody>
                {(data.recentScans || []).map((scan) => (
                  <tr key={scan.id}>
                    <td><span className="badge badge-muted">{scan.storageSource || '—'}</span></td>
                    <td>{scan.target}</td>
                    <td className="kpi-label">{formatDate(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  )
}

function KpiCard({ icon, value, label }) {
  return (
    <div className="card">
      <div className="kpi-icon">{icon}</div>
      <div className="kpi">{value}</div>
      <div className="kpi-label">{label}</div>
    </div>
  )
}
