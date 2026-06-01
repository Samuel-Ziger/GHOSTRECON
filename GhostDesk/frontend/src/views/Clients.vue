<template>
  <h2>Clientes</h2>
  <div class="card" style="margin-bottom:1rem">
    <div class="row">
      <input v-model="form.company" placeholder="Empresa *" />
      <input v-model="form.name" placeholder="Contato" />
      <input v-model="form.email" placeholder="E-mail" />
      <input v-model="form.phone" placeholder="Telefone" />
      <button class="primary" @click="create">Adicionar</button>
    </div>
    <p v-if="err" class="err">{{ err }}</p>
  </div>

  <div class="card">
    <table>
      <thead><tr><th>Empresa</th><th>Contato</th><th>E-mail</th><th>Projetos</th><th></th></tr></thead>
      <tbody>
        <tr v-for="c in clients" :key="c.id">
          <td>{{ c.company }}</td><td>{{ c.name }}</td><td>{{ c.email }}</td>
          <td>{{ c.projectCount }}</td>
          <td><button @click="remove(c.id)">Remover</button></td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../api/client'

const clients = ref([])
const form = ref({ company: '', name: '', email: '', phone: '' })
const err = ref('')

async function load() {
  const { data } = await api.get('/ghostdesk/clients')
  clients.value = data.clients
}
async function create() {
  err.value = ''
  if (!form.value.company) return
  try {
    await api.post('/ghostdesk/clients', form.value)
    form.value = { company: '', name: '', email: '', phone: '' }
    load()
  } catch (e) {
    err.value = e.response?.data?.error || 'erro ao salvar'
  }
}
async function remove(id) {
  await api.delete(`/ghostdesk/clients/${id}`)
  load()
}
onMounted(load)
</script>
