import { useEffect, useMemo, useState } from 'react'
import api from '../api/client.js'
import { badgeClass, formatDate, shortScanId } from '../lib/formatters.js'

export default function Scans() {
  const [scans, setScans] = useState([])
  const [projects, setProjects] = useState([])
  const [detail, setDetail] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [filter, setFilter] = useState('')
  const [storage, setStorage] = useState('')
  const [attachTo, setAttachTo] = useState('')
  const [attachMsg, setAttachMsg] = useState('')
  const [reporting, setReporting] = useState(false)
  const [error, setError] = useState('')

  const filtered = useMemo(() => {
    const query = filter.trim().toLowerCase()
    return query
      ? scans.filter((scan) => String(scan.target).toLowerCase().includes(query))
      : scans
  }, [filter, scans])

  const load = async () => {
    setError('')
    try {
      const [scanResponse, projectResponse] = await Promise.all([
        api.get('/ghostdesk/scans'),
        api.get('/ghostdesk/projects'),
      ])
      setScans(scanResponse.data.scans || [])
      setStorage(scanResponse.data.storage || '')
      setProjects(projectResponse.data.projects || [])
      window.dispatchEvent(new CustomEvent('ghostdesk-storage-meta', {
        detail: {
          storage: scanResponse.data.storage,
          remoteError: scanResponse.data.remoteError || '',
        },
      }))
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'erro ao carregar scans')
    }
  }

  useEffect(() => { void load() }, [])

  const openScan = async (id) => {
    setSelectedId(id)
    setAttachMsg('')
    setError('')
    try {
      const { data } = await api.get(`/ghostdesk/scans/${encodeURIComponent(id)}`)
      setDetail(data.scan)
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'erro ao abrir scan')
    }
  }

  const attach = async () => {
    try {
      await api.post(`/ghostdesk/scans/${encodeURIComponent(selectedId)}/attach`, { project: attachTo })
      setAttachMsg('✓ anexado')
    } catch (requestError) {
      setAttachMsg(requestError.response?.data?.error || 'erro')
    }
  }

  const report = async () => {
    setReporting(true)
    setAttachMsg('')
    try {
      const { data: reportPayload } = await api.get(
        `/ghostdesk/scans/${encodeURIComponent(selectedId)}/report-payload`,
      )
      const { data: handoff } = await api.post('/anotacao-handoff', { payload: reportPayload.payload })
      const base = `${window.location.protocol}//${window.location.hostname}:3847`
      window.open(`${base}${reportPayload.importPath}?handoff=${handoff.id}`, '_blank', 'noopener,noreferrer')
      setAttachMsg('✓ relatório aberto no GhostTrace')
    } catch (requestError) {
      setAttachMsg(requestError.response?.data?.error || 'erro ao gerar relatório')
    } finally {
      setReporting(false)
    }
  }

  return (
    <>
      <h2>Scans <span className="kpi-label">— runs do GHOSTRECON</span></h2>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="row">
          <div className="search-wrap" style={{ flex: 1 }}>
            <span className="search-prefix">$&gt;</span>
            <input value={filter} placeholder="filtrar por alvo…" onChange={(event) => setFilter(event.target.value)} />
          </div>
          <button type="button" onClick={() => void load()}>Recarregar</button>
          <span className="kpi-label">Origem: {storage}</span>
        </div>
        {error ? <p className="err" style={{ marginTop: '.5rem' }}>{error}</p> : null}
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h3>Runs</h3>
          <table>
            <thead><tr><th>ID</th><th>Origem</th><th>Alvo</th><th>Data</th><th /></tr></thead>
            <tbody>
              {filtered.map((scan) => (
                <tr key={scan.id} className={selectedId === scan.id ? 'selected' : undefined}>
                  <td className="kpi-label">{shortScanId(scan.id)}</td>
                  <td><span className="badge badge-muted">{scan.storageSource || '—'}</span></td>
                  <td>{scan.target}</td>
                  <td className="kpi-label">{formatDate(scan.created_at)}</td>
                  <td><button type="button" onClick={() => void openScan(scan.id)}>Abrir</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {detail ? (
          <div className="card">
            <h3>{detail.target}</h3>
            <div className="row" style={{ marginBottom: '.75rem' }}>
              <select value={attachTo} onChange={(event) => setAttachTo(event.target.value)}>
                <option value="" disabled>Anexar a projeto…</option>
                {projects.map((project) => (
                  <option key={project.name} value={project.name}>{project.name}</option>
                ))}
              </select>
              <button className="primary" type="button" onClick={() => void attach()} disabled={!attachTo}>Anexar</button>
              <button type="button" onClick={() => void report()} disabled={reporting}>
                {reporting ? 'Gerando…' : '📄 Relatório'}
              </button>
              {attachMsg ? <span className="kpi-label">{attachMsg}</span> : null}
            </div>
            <div className="kpi-label" style={{ marginBottom: '.6rem' }}>
              Findings: <strong className="detail-count">{(detail.findings || []).length}</strong>
            </div>
            <table>
              <thead><tr><th>Tipo</th><th>Prio</th><th>Score</th><th>Valor</th></tr></thead>
              <tbody>
                {(detail.findings || []).slice(0, 200).map((finding, index) => (
                  <tr key={finding.fingerprint || `${finding.type || 'finding'}-${index}`}>
                    <td>{finding.type}</td>
                    <td><span className={`badge ${badgeClass(finding.prio)}`}>{finding.prio || '—'}</span></td>
                    <td className="kpi-label">{finding.score ?? '—'}</td>
                    <td className="truncate" style={{ maxWidth: 280 }}>{finding.value || finding.url}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="card empty-state">
            <div className="empty-icon">▣</div>
            <div className="kpi-label">Selecione um scan para ver os detalhes</div>
          </div>
        )}
      </div>
    </>
  )
}
