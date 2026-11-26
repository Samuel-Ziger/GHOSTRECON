import { useState } from 'react'
import api from '../api/client.js'
import { badgeClass, formatDate } from '../lib/formatters.js'

export default function Intel() {
  const [target, setTarget] = useState('')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const load = async () => {
    const clean = target.trim()
    if (!clean) return
    setError('')
    setLoading(true)
    try {
      const { data: intel } = await api.get(`/ghostdesk/intel/${encodeURIComponent(clean)}`)
      setData(intel)
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'erro na consulta')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <h2>Intel <span className="kpi-label">— bounty_intel</span></h2>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="row">
          <div className="search-wrap" style={{ flex: 1 }}>
            <span className="search-prefix">$&gt;</span>
            <input
              value={target}
              placeholder="alvo (ex: example.com)"
              onChange={(event) => setTarget(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') void load()
              }}
            />
          </div>
          <button className="primary" type="button" onClick={() => void load()} disabled={loading}>
            {loading ? <span className="spinner small-spinner" /> : <span>Buscar</span>}
          </button>
        </div>
        {data?.remoteError ? <p className="err inline-error">Supabase: {data.remoteError}</p> : null}
        {error ? <p className="err inline-error">{error}</p> : null}
      </div>

      {data ? (
        <div className="card">
          <h3>{data.target}</h3>
          <div className="kpi-label intel-summary">{data.totalUnique} artefatos · origem {data.source}</div>
          <table>
            <thead><tr><th>Tipo</th><th>Prio</th><th>Score</th><th>Valor</th><th>Visto</th></tr></thead>
            <tbody>
              {(data.items || []).map((item, index) => (
                <tr key={item.id || item.fingerprint || `${item.type || 'intel'}-${index}`}>
                  <td>{item.type}</td>
                  <td><span className={`badge ${badgeClass(item.prio)}`}>{item.prio || '—'}</span></td>
                  <td className="kpi-label">{item.score ?? '—'}</td>
                  <td className="truncate" style={{ maxWidth: 320 }}>{item.value || item.url}</td>
                  <td className="kpi-label">{formatDate(item.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : !loading && !error ? (
        <div className="card empty-state">
          <div className="empty-icon">◎</div>
          <div className="kpi-label">Digite um alvo para consultar a base Intel</div>
        </div>
      ) : null}
    </>
  )
}
