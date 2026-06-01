import axios from 'axios'

/**
 * Cliente HTTP do GhostDesk → API do GHOSTRECON (mesma origem via proxy Vite).
 * Auth: reusa o fluxo do GHOSTRECON (auto-auth loopback → X-API-Key + CSRF).
 */
const api = axios.create({ baseURL: '/api' })

let apiKey = null
let csrfToken = null
let ready = null

async function bootstrap() {
  // 1) chave (loopback). Se auth estiver desabilitada/sem chave, segue sem header.
  try {
    const { data } = await axios.get('/api/setup/auto-auth')
    apiKey = data.apiKey || null
  } catch {
    apiKey = null
  }
  // 2) token CSRF (defesa em profundidade nas mutações)
  try {
    const { data } = await axios.get('/api/csrf-token')
    csrfToken = data.token || null
  } catch {
    csrfToken = null
  }
}

export function ensureAuth() {
  if (!ready) ready = bootstrap()
  return ready
}

api.interceptors.request.use(async (config) => {
  await ensureAuth()
  if (apiKey) config.headers['X-API-Key'] = apiKey
  if (csrfToken) config.headers['X-CSRF-Token'] = csrfToken
  return config
})

export default api
