import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'

async function source(relativePath) {
  return fs.readFile(new URL(`../${relativePath}`, import.meta.url), 'utf8')
}

test('cliente HTTP React preserva auto-auth, CSRF, headers e toggle Supabase', async () => {
  const client = await source('src/api/client.js')
  assert.match(client, /axios\.get\('\/api\/setup\/auto-auth'\)/)
  assert.match(client, /axios\.get\('\/api\/csrf-token'\)/)
  assert.match(client, /config\.headers\['X-API-Key'\]/)
  assert.match(client, /config\.headers\['X-CSRF-Token'\]/)
  assert.match(client, /ghostdesk_use_supabase/)
  assert.match(client, /ghostdesk-supabase-toggle/)
  assert.match(client, /supabase:\s*'1'/)
})

test('telas React preservam todos os endpoints e o handoff GhostTrace', async () => {
  const [layout, scans, projects, clients, intel] = await Promise.all([
    source('src/components/AppLayout.jsx'),
    source('src/views/Scans.jsx'),
    source('src/views/Projects.jsx'),
    source('src/views/Clients.jsx'),
    source('src/views/Intel.jsx'),
  ])

  assert.match(layout, /\/ghostdesk\/config/)
  assert.match(layout, /\/ghostdesk\/search/)
  assert.match(scans, /\/ghostdesk\/scans/)
  assert.match(scans, /\/ghostdesk\/projects/)
  assert.match(scans, /report-payload/)
  assert.match(scans, /\/anotacao-handoff/)
  assert.match(scans, /\?handoff=\$\{handoff\.id\}/)
  assert.match(projects, /\/ghostdesk\/projects/)
  assert.match(projects, /\/ghostdesk\/clients/)
  assert.match(projects, /\/client`/)
  assert.match(clients, /api\.post\('\/ghostdesk\/clients'/)
  assert.match(clients, /api\.delete\(`/)
  assert.match(intel, /\/ghostdesk\/intel\//)
})
