<template>
  <div class="layout">
    <nav class="sidebar">

      <!-- Marca — Orbitron + glow ciano -->
      <div class="sidebar-brand">
        <h1><span>GHOST</span>DESK</h1>
        <div class="brand-sub">
          <span class="status-dot"></span>
          módulo GHOSTRECON
        </div>
      </div>

      <!-- Navegação -->
      <div class="nav-section">SISTEMA</div>
      <router-link to="/dashboard"><span class="nav-icon">◈</span>Dashboard</router-link>
      <router-link to="/scans"><span class="nav-icon">⊕</span>Scans</router-link>
      <router-link to="/projects"><span class="nav-icon">⊞</span>Projetos</router-link>
      <router-link to="/clients"><span class="nav-icon">⊙</span>Clientes</router-link>
      <router-link to="/intel"><span class="nav-icon">◎</span>Intel</router-link>

      <!-- Storage toggle -->
      <div class="nav-section" style="margin-top:.5rem">STORAGE</div>
      <div class="card" style="margin-top:.25rem;padding:.65rem;border-radius:2px">
        <label class="toggle-row">
          <div class="pill-toggle" :class="{ 'is-on': supabaseOn, 'is-disabled': !remoteConfigured }">
            <input type="checkbox" v-model="supabaseOn" :disabled="!remoteConfigured" @change="onToggle" />
            <div class="pill-track"></div>
            <div class="pill-thumb"></div>
          </div>
          <span>Buscar no Supabase</span>
        </label>
        <div class="kpi-label" style="margin-top:.35rem">
          {{ supabaseOn ? 'SQLite + nuvem' : 'Só SQLite local' }}
        </div>
        <div v-if="remoteError" class="err" style="margin-top:.35rem">{{ remoteError }}</div>
        <div v-else-if="!remoteConfigured" class="kpi-label" style="margin-top:.35rem">Supabase não configurado</div>
      </div>

      <div style="flex:1"></div>

      <!-- Status rodapé -->
      <div class="storage-status">
        <span class="status-dot" style="background:var(--accent2)"></span>
        <span class="kpi-label">{{ storage }}</span>
      </div>
    </nav>

    <main class="content">
      <!-- Busca global com prefixo $> estilo terminal -->
      <div class="row" style="margin-bottom:1.25rem">
        <div class="search-wrap">
          <span class="search-prefix">$&gt;</span>
          <input v-model="q" placeholder="busca global (clientes, projetos, scans)…" @keyup.enter="search" />
        </div>
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

      <router-view :key="viewKey" />
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api, { getUseSupabase, setUseSupabase } from '../api/client'

const q = ref('')
const results = ref(null)
const storage = ref('SQLite local')
const supabaseOn = ref(getUseSupabase())
const remoteConfigured = ref(false)
const remoteError = ref('')
const viewKey = ref(0)

function onStorageEvent(e) {
  if (e?.detail?.storage) storage.value = e.detail.storage
  if (e?.detail?.remoteError != null) remoteError.value = e.detail.remoteError
}

function onToggle() {
  setUseSupabase(supabaseOn.value)
  viewKey.value += 1
}

async function search() {
  if (q.value.trim().length < 2) return
  const { data } = await api.get('/ghostdesk/search', { params: { q: q.value } })
  results.value = data
}

onMounted(async () => {
  window.addEventListener('ghostdesk-storage-meta', onStorageEvent)
  try {
    const { data } = await api.get('/ghostdesk/config')
    remoteConfigured.value = Boolean(data.remoteConfigured)
    storage.value = data.storageLabel || 'SQLite local'
    if (!remoteConfigured.value && supabaseOn.value) {
      supabaseOn.value = false
      setUseSupabase(false)
    }
  } catch (_) {}
})
</script>
