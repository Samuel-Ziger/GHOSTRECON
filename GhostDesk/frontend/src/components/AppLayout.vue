<template>
  <div class="layout">
    <nav class="sidebar">
      <h1>GHOSTDESK</h1>
      <div class="kpi-label" style="margin:-.5rem 0 1rem">módulo GHOSTRECON</div>
      <router-link to="/dashboard">Dashboard</router-link>
      <router-link to="/scans">Scans</router-link>
      <router-link to="/projects">Projetos</router-link>
      <router-link to="/clients">Clientes</router-link>
      <router-link to="/intel">Intel (Supabase)</router-link>
      <div style="flex:1"></div>
      <div class="kpi-label" style="padding:.5rem .7rem">{{ storage }}</div>
    </nav>
    <main class="content">
      <div class="row" style="margin-bottom:1rem">
        <input v-model="q" placeholder="Busca global (clientes, projetos, scans)…" style="flex:1" @keyup.enter="search" />
        <button class="primary" @click="search">Buscar</button>
      </div>
      <div v-if="results" class="card" style="margin-bottom:1rem">
        <strong>Resultados para "{{ results.query }}"</strong>
        <div class="grid cols-2" style="margin-top:.6rem">
          <div v-for="(items, k) in results.results" :key="k">
            <div class="kpi-label">{{ k }} ({{ items.length }})</div>
            <div v-for="(it, i) in items" :key="k + i" style="font-size:.85rem">
              {{ it.company || it.name || it.target }}
            </div>
          </div>
        </div>
      </div>
      <router-view />
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../api/client'

const q = ref('')
const results = ref(null)
const storage = ref('')

async function search() {
  if (q.value.trim().length < 2) return
  const { data } = await api.get('/ghostdesk/search', { params: { q: q.value } })
  results.value = data
}
onMounted(async () => {
  try {
    const { data } = await api.get('/ghostdesk/overview')
    storage.value = data.usingSupabase ? 'Supabase' : data.storage
  } catch (_) {}
})
</script>
