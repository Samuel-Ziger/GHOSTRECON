import axios from 'axios'

/**
 * Cliente HTTP do GhostDesk → API do GHOSTRECON (mesma origem via proxy Vite).
 * Auth: reusa o fluxo do GHOSTRECON (auto-auth loopback → X-API-Key + CSRF).
 * Storage: SQLite por defeito; ?supabase=1 quando o interruptor está ligado.
 */
const api = axios.create({ baseURL: '/api' })

const STORAGE_KEY = 'ghostdesk_use_supabase'

let apiKey = null
let csrfToken = null
let ready = null
let useSupabase = typeof localStorage !== 'undefined' && localStorage.getItem(STORAGE_KEY) === '1'

export function getUseSupabase() {
  return useSupabase
}

export function setUseSupabase(on) {
  useSupabase = Boolean(on)
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, useSupabase ? '1' : '0')
  }
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('ghostdesk-supabase-toggle', { detail: { on: useSupabase } }))
  }
}

async function bootstrap() {
  try {
    const { data } = await axios.get('/api/setup/auto-auth')
    apiKey = data.apiKey || null
  } catch {
    apiKey = null
  }
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
  const url = String(config.url || '')
  if (useSupabase && url.includes('/ghostdesk/')) {
    config.params = { ...config.params, supabase: '1' }
  }
  return config
})

export default api
