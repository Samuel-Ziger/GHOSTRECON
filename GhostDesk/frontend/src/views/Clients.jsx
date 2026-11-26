import { useEffect, useState } from 'react'
import api from '../api/client.js'

const EMPTY_FORM = Object.freeze({ company: '', name: '', email: '', phone: '' })

export default function Clients() {
  const [clients, setClients] = useState([])
  const [form, setForm] = useState({ ...EMPTY_FORM })
  const [error, setError] = useState('')

  const load = async () => {
    const { data } = await api.get('/ghostdesk/clients')
    setClients(data.clients || [])
  }

  useEffect(() => {
    load().catch((requestError) => {
      setError(requestError.response?.data?.error || 'erro ao carregar clientes')
    })
  }, [])

  const updateField = (field) => (event) => {
    setForm((current) => ({ ...current, [field]: event.target.value }))
  }

  const create = async () => {
    setError('')
    if (!form.company.trim()) return
    try {
      await api.post('/ghostdesk/clients', form)
      setForm({ ...EMPTY_FORM })
      await load()
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'erro ao salvar')
    }
  }

  const remove = async (id) => {
    setError('')
    try {
      await api.delete(`/ghostdesk/clients/${encodeURIComponent(id)}`)
      await load()
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'erro ao remover')
    }
  }

  return (
    <>
      <h2>Clientes</h2>
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="row">
          <input value={form.company} onChange={updateField('company')} placeholder="Empresa *" />
          <input value={form.name} onChange={updateField('name')} placeholder="Contato" />
          <input value={form.email} onChange={updateField('email')} placeholder="E-mail" />
          <input value={form.phone} onChange={updateField('phone')} placeholder="Telefone" />
          <button className="primary" type="button" onClick={() => void create()}>Adicionar</button>
        </div>
        {error ? <p className="err" style={{ marginTop: '.5rem' }}>{error}</p> : null}
      </div>

      <div className="card">
        <table>
          <thead><tr><th>Empresa</th><th>Contato</th><th>E-mail</th><th>Projetos</th><th /></tr></thead>
          <tbody>
            {clients.map((client) => (
              <tr key={client.id}>
                <td>{client.company}</td>
                <td>{client.name}</td>
                <td>{client.email}</td>
                <td>{client.projectCount}</td>
                <td><button type="button" onClick={() => void remove(client.id)}>Remover</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
