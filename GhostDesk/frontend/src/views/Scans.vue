<template>
  <h2>Scans <span class="kpi-label">— runs do GHOSTRECON</span></h2>

  <div class="card" style="margin-bottom:1rem">
    <div class="row">
      <div class="search-wrap" style="flex:1">
        <span class="search-prefix">$&gt;</span>
        <input v-model="filter" placeholder="filtrar por alvo…" />
      </div>
      <button @click="load">Recarregar</button>
      <span class="kpi-label">Origem: {{ storage }}</span>
    </div>
  </div>

  <div class="grid cols-2">
    <div class="card">
      <h3>Runs</h3>
      <table>
        <thead><tr><th>ID</th><th>Origem</th><th>Alvo</th><th>Data</th><th></th></tr></thead>
        <tbody>
          <tr v-for="s in filtered" :key="s.id" :class="{ selected: selectedId === s.id }">
            <td class="kpi-label">{{ shortId(s.id) }}</td>
            <td><span class="badge badge-muted">{{ s.storageSource || '—' }}</span></td>
            <td>{{ s.target }}</td>
            <td class="kpi-label">{{ fmt(s.created_at) }}</td>
            <td><button @click="open(s.id)">Abrir</button></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card" v-if="detail">
      <h3>{{ detail.target }}</h3>
      <div class="row" style="margin-bottom:.75rem">
        <select v-model="attachTo">
          <option value="" disabled>Anexar a projeto…</option>
          <option v-for="p in projects" :key="p.name" :value="p.name">{{ p.name }}</option>
        </select>
        <button class="primary" @click="attach" :disabled="!attachTo">Anexar</button>
        <button @click="report" :disabled="reporting">{{ reporting ? 'Gerando…' : '📄 Relatório' }}</button>
        <span v-if="attachMsg" class="kpi-label">{{ attachMsg }}</span>
      </div>
      <div class="kpi-label" style="margin-bottom:.6rem">
        Findings: <strong style="color:var(--text-bright);font-family:var(--display);font-size:.85rem">{{ (detail.findings || []).length }}</strong>
      </div>
      <table>
        <thead><tr><th>Tipo</th><th>Prio</th><th>Score</th><th>Valor</th></tr></thead>
        <tbody>
          <tr v-for="(f, i) in (detail.findings || []).slice(0, 200)" :key="i">
            <td>{{ f.type }}</td>
            <td><span class="badge" :class="badgeClass(f.prio)">{{ f.prio || '—' }}</span></td>
            <td class="kpi-label">{{ f.score ?? '—' }}</td>
            <td class="truncate" style="max-width:280px">{{ f.value || f.url }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card empty-state" v-else>
      <div class="empty-icon">▣</div>
      <div class="kpi-label">Selecione um scan para ver os detalhes</div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api/client'

const scans = ref([])
const projects = ref([])
const detail = ref(null)
const selectedId = ref(null)
const filter = ref('')
const storage = ref('')
const attachTo = ref('')
const attachMsg = ref('')
const reporting = ref(false)

const filtered = computed(() =>
  filter.value.trim()
    ? scans.value.filter((s) => String(s.target).toLowerCase().includes(filter.value.toLowerCase()))
    : scans.value,
)
const map = { critical: 'sev-critical', high: 'sev-high', med: 'sev-medium', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' }
const badgeClass = (p) => map[String(p || '').toLowerCase()] || 'sev-info'
const fmt = (d) => (d ? new Date(d).toLocaleString() : '—')
const shortId = (id) => {
  const s = String(id || '')
  if (s.startsWith('scope:')) return s.replace(/^scope:([^:]+):(\d+)$/, (_, p, n) => `${decodeURIComponent(p)} #${n}`)
  if (s.includes(':')) return s.split(':').slice(-2).join(':')
  return `#${s}`
}

async function load() {
  const [s, p] = await Promise.all([api.get('/ghostdesk/scans'), api.get('/ghostdesk/projects')])
  scans.value = s.data.scans
  storage.value = s.data.storage
  projects.value = p.data.projects
  window.dispatchEvent(
    new CustomEvent('ghostdesk-storage-meta', {
      detail: { storage: s.data.storage, remoteError: s.data.remoteError || '' },
    }),
  )
}
async function open(id) {
  selectedId.value = id
  attachMsg.value = ''
  const { data } = await api.get(`/ghostdesk/scans/${encodeURIComponent(id)}`)
  detail.value = data.scan
}
async function attach() {
  try {
    await api.post(`/ghostdesk/scans/${encodeURIComponent(selectedId.value)}/attach`, { project: attachTo.value })
    attachMsg.value = '✓ anexado'
  } catch (e) {
    attachMsg.value = e.response?.data?.error || 'erro'
  }
}
async function report() {
  reporting.value = true
  attachMsg.value = ''
  try {
    const { data: r } = await api.get(`/ghostdesk/scans/${encodeURIComponent(selectedId.value)}/report-payload`)
    const { data: h } = await api.post('/anotacao-handoff', { payload: r.payload })
    const base = `${location.protocol}//${location.hostname}:3847`
    window.open(`${base}${r.importPath}?handoff=${h.id}`, '_blank')
    attachMsg.value = '✓ relatório aberto no GhostTrace'
  } catch (e) {
    attachMsg.value = e.response?.data?.error || 'erro ao gerar relatório'
  } finally {
    reporting.value = false
  }
}
onMounted(load)
</script>
