<template>
  <h2>Intel <span class="kpi-label">— bounty_intel</span></h2>

  <div class="card" style="margin-bottom:1rem">
    <div class="row">
      <div class="search-wrap" style="flex:1">
        <span class="search-prefix">$&gt;</span>
        <input v-model="target" placeholder="alvo (ex: example.com)" @keyup.enter="load" />
      </div>
      <button class="primary" @click="load" :disabled="loading">
        <span v-if="loading" class="spinner" style="width:.9rem;height:.9rem;border-width:1px;vertical-align:middle"></span>
        <span v-else>Buscar</span>
      </button>
    </div>
    <p v-if="data?.remoteError" class="err" style="margin:.5rem 0 0">Supabase: {{ data.remoteError }}</p>
    <p v-if="err" class="err" style="margin:.5rem 0 0">{{ err }}</p>
  </div>

  <div v-if="data" class="card">
    <h3>{{ data.target }}</h3>
    <div class="kpi-label" style="margin-top:-.3rem;margin-bottom:.75rem">{{ data.totalUnique }} artefatos · origem {{ data.source }}</div>
    <table>
      <thead><tr><th>Tipo</th><th>Prio</th><th>Score</th><th>Valor</th><th>Visto</th></tr></thead>
      <tbody>
        <tr v-for="(it, i) in data.items" :key="i">
          <td>{{ it.type }}</td>
          <td><span class="badge" :class="badgeClass(it.prio)">{{ it.prio || '—' }}</span></td>
          <td class="kpi-label">{{ it.score ?? '—' }}</td>
          <td class="truncate" style="max-width:320px">{{ it.value || it.url }}</td>
          <td class="kpi-label">{{ fmt(it.last_seen) }}</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div v-else-if="!loading && !err" class="card empty-state">
    <div class="empty-icon">◎</div>
    <div class="kpi-label">Digite um alvo para consultar a base Intel</div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import api from '../api/client'

const target = ref('')
const data = ref(null)
const loading = ref(false)
const err = ref('')
const map = { critical: 'sev-critical', high: 'sev-high', med: 'sev-medium', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' }
const badgeClass = (p) => map[String(p || '').toLowerCase()] || 'sev-info'
const fmt = (d) => (d ? new Date(d).toLocaleString() : '—')

async function load() {
  if (!target.value.trim()) return
  err.value = ''
  loading.value = true
  try {
    const { data: d } = await api.get(`/ghostdesk/intel/${encodeURIComponent(target.value.trim())}`)
    data.value = d
  } catch (e) {
    err.value = e.response?.data?.error || 'erro na consulta'
  } finally {
    loading.value = false
  }
}
</script>
