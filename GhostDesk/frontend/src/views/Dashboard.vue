<template>
  <h2>Dashboard</h2>
  <div v-if="data" class="grid cols-4">
    <div class="card"><div class="kpi">{{ data.totals.scans }}</div><div class="kpi-label">Scans (runs)</div></div>
    <div class="card"><div class="kpi">{{ data.totals.targets }}</div><div class="kpi-label">Alvos únicos</div></div>
    <div class="card"><div class="kpi">{{ data.totals.projects }}</div><div class="kpi-label">Projetos</div></div>
    <div class="card"><div class="kpi">{{ data.totals.clients }}</div><div class="kpi-label">Clientes</div></div>
  </div>

  <div v-if="data" class="grid cols-2" style="margin-top:1rem">
    <div class="card">
      <h3>Findings por prioridade <span class="kpi-label">(amostra de runs recentes)</span></h3>
      <div v-for="(n, p) in data.findingsBySeverity" :key="p" class="row" style="justify-content:space-between;padding:.3rem 0">
        <span class="badge" :class="badgeClass(p)">{{ p }}</span>
        <strong>{{ n }}</strong>
      </div>
      <div v-if="!Object.keys(data.findingsBySeverity).length" class="kpi-label">Nenhum finding ainda.</div>
    </div>
    <div class="card">
      <h3>Armazenamento</h3>
      <div class="kpi" style="color:var(--accent)">{{ data.usingSupabase ? 'Supabase' : data.storage }}</div>
      <div class="kpi-label">Origem dos scans/intel consumidos pelo GhostDesk</div>
    </div>
  </div>

  <div v-if="data" class="card" style="margin-top:1rem">
    <h3>Scans recentes</h3>
    <table>
      <thead><tr><th>ID</th><th>Alvo</th><th>Data</th></tr></thead>
      <tbody>
        <tr v-for="s in data.recentScans" :key="s.id">
          <td>#{{ s.id }}</td><td>{{ s.target }}</td><td>{{ fmt(s.created_at) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../api/client'

const data = ref(null)
const map = { critical: 'sev-critical', high: 'sev-high', med: 'sev-medium', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' }
const badgeClass = (p) => map[p] || 'sev-info'
const fmt = (d) => (d ? new Date(d).toLocaleString() : '—')

onMounted(async () => {
  const { data: d } = await api.get('/ghostdesk/overview')
  data.value = d
})
</script>
