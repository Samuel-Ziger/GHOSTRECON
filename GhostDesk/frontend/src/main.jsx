import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import './style.css'

const root = document.getElementById('app')

if (!root) {
  throw new Error('GhostDesk: elemento #app não encontrado')
}

createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
