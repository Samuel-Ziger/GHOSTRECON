<template>
  <h2>Dashboard</h2>

  <div v-if="!data" class="loading-wrap">
    <span class="spinner"></span>
  </div>

  <template v-if="data">
    <div class="grid cols-4">
      <div class="card">
        <div class="kpi-icon">⬡</div>
        <div class="kpi">{{ data.totals.scans }}</div>
        <div class="kpi-label">Scans (runs)</div>
      </div>
      <div class="card">
        <div class="kpi-icon">◎</div>
        <div class="kpi">{{ data.totals.targets }}</div>
        <div class="kpi-label">Alvos únicos</div>
      </div>
      <div class="card">
        <div class="kpi-icon">⊞</div>
        <div class="kpi">{{ data.totals.projects }}</div>
        <div class="kpi-label">Projetos</div>
      </div>
      <div class="card">
        <div class="kpi-icon">⊙</div>
        <div class="kpi">{{ data.totals.clients }}</div>
        <div class="kpi-label">Clientes</div>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:1rem">
      <div class="card">
        <h3>Findings por prioridade</h3>
        <div v-for="(n, p) in data.findingsBySeverity" :key="p" class="sev-row">
          <span class="badge" :class="badgeClass(p)" style="min-width:5rem;text-align:center">{{ p }}</span>
          <div class="sev-bar-wrap">
            <div class="sev-bar">
              <div class="sev-bar-fill" :style="{ width: barWidth(n) + '%', background: sevColor(p) }"></div>
            </div>
            <strong style="min-width:2.2rem;text-align:right;font-variant-numeric:tabular-nums;font-family:var(--mono);font-size:.8rem">{{ n }}</strong>
          </div>
        </div>
        <div v-if="!Object.keys(data.findingsBySeverity).length" class="kpi-label" style="padding:.5rem 0">Nenhum finding ainda.</div>
      </div>

      <div class="card">
        <h3>Armazenamento</h3>
        <div class="kpi">{{ data.storage }}</div>
        <div v-if="data.sources" style="margin-top:.55rem;display:flex;flex-wrap:wrap;gap:.4rem">
          <span v-for="(n, k) in data.sources" :key="k" class="badge badge-muted">
            {{ k }}&nbsp;<strong style="color:var(--text)">{{ n }}</strong>
          </span>
        </div>
        <div class="kpi-label" style="margin-top:.6rem">SQLite local + escopo + Supabase quando online</div>
      </div>
    </div>

    <div class="card" style="margin-top:1rem">
      <h3>Scans recentes</h3>
      <table>
        <thead><tr><th>Origem</th><th>Alvo</th><th>Data</th></tr></thead>
        <tbody>
          <tr v-for="s in data.recentScans" :key="s.id">
            <td><span class="badge badge-muted">{{ s.storageSource || '—' }}</span></td>
            <td>{{ s.target }}</td>
            <td class="kpi-label">{{ fmt(s.created_at) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api/client'

const data = ref(null)
const map = { critical: 'sev-critical', high: 'sev-high', med: 'sev-medium', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' }
const badgeClass = (p) => map[p] || 'sev-info'
const fmt = (d) => (d ? new Date(d).toLocaleString() : '—')

const maxSev = computed(() => Math.max(...Object.values(data.value?.findingsBySeverity || {}), 1))
const barWidth = (n) => Math.round((n / maxSev.value) * 100)
const sevColorMap = { critical: '#ff3366', high: '#ff8a3d', med: '#ffd23d', medium: '#ffd23d', low: '#3dd6a8', info: '#5a9bd4' }
const sevColor = (p) => sevColorMap[p] || '#5a9bd4'

onMounted(async () => {
  const { data: d } = await api.get('/ghostdesk/overview')
  data.value = d
  window.dispatchEvent(
    new CustomEvent('ghostdesk-storage-meta', {
      detail: { storage: d.storage, remoteError: d.remoteError || '' },
    }),
  )
})
</script>
