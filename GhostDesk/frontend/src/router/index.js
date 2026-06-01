import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    component: () => import('../components/AppLayout.vue'),
    children: [
      { path: '', redirect: '/dashboard' },
      { path: 'dashboard', name: 'dashboard', component: () => import('../views/Dashboard.vue') },
      { path: 'scans', name: 'scans', component: () => import('../views/Scans.vue') },
      { path: 'projects', name: 'projects', component: () => import('../views/Projects.vue') },
      { path: 'clients', name: 'clients', component: () => import('../views/Clients.vue') },
      { path: 'intel', name: 'intel', component: () => import('../views/Intel.vue') },
    ],
  },
]

export default createRouter({ history: createWebHashHistory(), routes })
