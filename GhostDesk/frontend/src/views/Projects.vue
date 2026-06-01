<template>
  <h2>Projetos <span class="kpi-label">— programas do GHOSTRECON</span></h2>

  <div class="card">
    <table>
      <thead><tr><th>Projeto</th><th>Cliente</th><th>Escopo</th><th>Runs</th><th>Vincular cliente</th></tr></thead>
      <tbody>
        <tr v-for="p in projects" :key="p.name">
          <td>{{ p.name }}</td>
          <td>{{ p.client?.company || '—' }}</td>
          <td class="kpi-label">{{ (p.scope || []).join(', ') || '—' }}</td>
          <td>{{ p.runCount }}</td>
          <td>
            <div class="row">
              <select v-model="link[p.name]">
                <option value="" disabled>cliente…</option>
                <option v-for="c in clients" :key="c.id" :value="c.id">{{ c.company }}</option>
              </select>
              <button @click="assign(p.name)" :disabled="!link[p.name]">OK</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <p class="kpi-label" style="margin-top:.6rem">
      Projetos são criados pelo GHOSTRECON (CLI/scheduler). Aqui você os vincula a clientes.
    </p>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../api/client'

const projects = ref([])
const clients = ref([])
const link = ref({})

async function load() {
  const [p, c] = await Promise.all([api.get('/ghostdesk/projects'), api.get('/ghostdesk/clients')])
  projects.value = p.data.projects
  clients.value = c.data.clients
}
async function assign(name) {
  await api.post(`/ghostdesk/projects/${encodeURIComponent(name)}/client`, { clientId: link.value[name] })
  load()
}
onMounted(load)
</script>
