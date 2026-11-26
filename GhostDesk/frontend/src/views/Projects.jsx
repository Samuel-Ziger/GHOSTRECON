import { useEffect, useState } from 'react'
import api from '../api/client.js'

export default function Projects() {
  const [projects, setProjects] = useState([])
  const [clients, setClients] = useState([])
  const [links, setLinks] = useState({})
  const [error, setError] = useState('')

  const load = async () => {
    setError('')
    try {
      const [projectResponse, clientResponse] = await Promise.all([
        api.get('/ghostdesk/projects'),
        api.get('/ghostdesk/clients'),
      ])
      setProjects(projectResponse.data.projects || [])
      setClients(clientResponse.data.clients || [])
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'erro ao carregar projetos')
    }
  }

  useEffect(() => { void load() }, [])

  const assign = async (name) => {
    const clientId = links[name]
    if (!clientId) return
    setError('')
    try {
      await api.post(`/ghostdesk/projects/${encodeURIComponent(name)}/client`, { clientId })
      await load()
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'erro ao vincular cliente')
    }
  }

  return (
    <>
      <h2>Projetos <span className="kpi-label">— programas do GHOSTRECON</span></h2>
      {error ? <p className="err" style={{ marginBottom: '1rem' }}>{error}</p> : null}
      <div className="card">
        <table>
          <thead><tr><th>Projeto</th><th>Cliente</th><th>Escopo</th><th>Runs</th><th>Vincular cliente</th></tr></thead>
          <tbody>
            {projects.map((project) => (
              <tr key={project.name}>
                <td>{project.name}</td>
                <td>{project.client?.company || '—'}</td>
                <td className="kpi-label">{(project.scope || []).join(', ') || '—'}</td>
                <td>{project.runCount}</td>
                <td>
                  <div className="row">
                    <select
                      value={links[project.name] || ''}
                      onChange={(event) => setLinks((current) => ({
                        ...current,
                        [project.name]: event.target.value,
                      }))}
                    >
                      <option value="" disabled>cliente…</option>
                      {clients.map((client) => (
                        <option key={client.id} value={client.id}>{client.company}</option>
                      ))}
                    </select>
                    <button
                      type="button"
                      onClick={() => void assign(project.name)}
                      disabled={!links[project.name]}
                    >
                      OK
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="kpi-label" style={{ marginTop: '.6rem' }}>
          Projetos são criados pelo GHOSTRECON (CLI/scheduler). Aqui você os vincula a clientes.
        </p>
      </div>
    </>
  )
}
