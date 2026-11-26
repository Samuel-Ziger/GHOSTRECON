import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.jsx';
import '../style.css';

const path = window.location.pathname.toLowerCase();
const page = path.endsWith('/dicas.html') || path.endsWith('dicas.html') ? 'tips' : 'home';

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App page={page} />
  </React.StrictMode>,
);
