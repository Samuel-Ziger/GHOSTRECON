<template>
  <h2>Intel <span class="kpi-label">— corpus deduplicado (Supabase / bounty_intel)</span></h2>

  <div class="card" style="margin-bottom:1rem">
    <div class="row">
      <input v-model="target" placeholder="alvo (ex: example.com)" style="flex:1" @keyup.enter="load" />
      <button class="primary" @click="load" :disabled="loading">{{ loading ? 'Buscando…' : 'Buscar' }}</button>
    </div>
    <p v-if="err" class="err">{{ err }}</p>
  </div>

  <div v-if="data" class="card">
    <div class="row" style="justify-content:space-between">
      <h3 style="margin:0">{{ data.target }}</h3>
      <span class="kpi-label">{{ data.totalUnique }} artefatos · origem {{ data.source }}</span>
    </div>
    <table style="margin-top:.6rem">
      <thead><tr><th>Tipo</th><th>Prio</th><th>Score</th><th>Valor</th><th>Visto</th></tr></thead>
      <tbody>
        <tr v-for="(it, i) in data.items" :key="i">
          <td>{{ it.type }}</td>
          <td><span class="badge" :class="badgeClass(it.prio)">{{ it.prio || '—' }}</span></td>
          <td>{{ it.score ?? '—' }}</td>
          <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ it.value || it.url }}</td>
          <td class="kpi-label">{{ fmt(it.last_seen) }}</td>
        </tr>
      </tbody>
    </table>
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
