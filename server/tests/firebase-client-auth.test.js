import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractFirebaseConfig,
  detectClientSideRbac,
} from '../modules/firebase-audit.mjs';
import {
  auditClientSideAuth,
  mergeClientAuthFindings,
} from '../modules/client-auth-audit.mjs';

const firebaseBundle = `
  const firebaseConfig = {
    apiKey: "AIzaSyBlEgFftjgHDznfDiLGxTup9otxIxE6B4U",
    authDomain: "my-app.firebaseapp.com",
    projectId: "my-app",
    storageBucket: "my-app.appspot.com",
    databaseURL: "https://my-app-default-rtdb.firebaseio.com"
  };
  import { signInWithEmailAndPassword } from 'firebase/auth';
  router.beforeEach((to) => hasRole('ADMIN'));
  // permissions.js
`;

test('firebase-audit: extractFirebaseConfig parseia firebaseConfig', () => {
  const cfg = extractFirebaseConfig(firebaseBundle);
  assert.ok(cfg);
  assert.equal(cfg.projectId, 'my-app');
  assert.ok(cfg.apiKey.startsWith('AIza'));
  assert.ok(cfg.firestoreUrl.includes('my-app'));
  assert.ok(cfg.databaseURL.includes('firebaseio.com'));
});

test('firebase-audit: detectClientSideRbac sinaliza RBAC client-side', () => {
  const f = detectClientSideRbac(firebaseBundle);
  assert.ok(f);
  assert.equal(f.type, 'firebase_client_side_rbac');
});

const camilaBundle = `
  if (sessionStorage.getItem("cf-admin") === "ok") showPanel();
  const senha = "SuperSecretAdmin2026!";
  if (password === senha) { router.push("/painel-campanhas"); }
  sessionStorage.setItem("cf-contatos", JSON.stringify(contacts));
  localStorage.setItem("cf-campanhas", data);
  path: "/painel-campanhas/dashboard"
`;

test('client-auth-audit: detecta bypass sessionStorage', () => {
  const { findings } = auditClientSideAuth(camilaBundle, { url: 'https://example.com/app.js' });
  const bypass = findings.find((f) => f.type === 'client_storage_auth_bypass');
  assert.ok(bypass);
  assert.ok(bypass.meta.gates.some((g) => g.key === 'cf-admin'));
});

test('client-auth-audit: detecta credencial hardcoded', () => {
  const { findings } = auditClientSideAuth('if (password === "MyAdminPass123!") login();');
  assert.ok(findings.find((f) => f.type === 'client_hardcoded_credential'));
});

test('client-auth-audit: detecta painel no bundle público', () => {
  const { findings } = auditClientSideAuth(camilaBundle);
  assert.ok(findings.find((f) => f.type === 'client_admin_panel_in_public_bundle'));
});

test('client-auth-audit: mergeClientAuthFindings deduplica', () => {
  const a = auditClientSideAuth(camilaBundle);
  const b = auditClientSideAuth(camilaBundle);
  const merged = mergeClientAuthFindings([a, b]);
  assert.ok(merged.length <= a.findings.length + 1);
});
