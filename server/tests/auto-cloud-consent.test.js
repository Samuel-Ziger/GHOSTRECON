import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertCloudEvidenceConsent,
  buildAgentPrompt,
  isCloudDataPlaneProvider,
} from '../auto-agent/providers/shared.mjs';

test('openrouter é data plane cloud', () => {
  assert.equal(isCloudDataPlaneProvider('openrouter'), true);
  assert.equal(isCloudDataPlaneProvider('codex'), false);
  assert.equal(isCloudDataPlaneProvider('local_model', 'cloud'), true);
});

test('assertCloudEvidenceConsent falha fechado sem consentimento', () => {
  assert.throws(
    () => assertCloudEvidenceConsent({ providerId: 'openrouter', cloudEvidenceConsent: false }),
    (error) => error?.code === 'CLOUD_EVIDENCE_CONSENT_REQUIRED',
  );
  assert.doesNotThrow(() => assertCloudEvidenceConsent({
    providerId: 'openrouter',
    cloudEvidenceConsent: true,
  }));
  assert.doesNotThrow(() => assertCloudEvidenceConsent({
    providerId: 'codex',
    cloudEvidenceConsent: false,
  }));
});

test('buildAgentPrompt redige evidência cloud sem consentimento', () => {
  const prompt = buildAgentPrompt({
    target: 'secret.example.test',
    mode: 'balanced',
    catalog: { modules: [{ id: 'headers', class: 'passive', available: true }] },
    ragContext: { items: [{ name: 'notes/a.md', title: 'segredo', preview: 'token=abc' }] },
    observationBundle: { findings: [{ ref: 'f1', value: 'leak' }] },
    cloudEvidenceConsent: false,
    dataPlane: 'cloud',
    providerId: 'openrouter',
  });
  assert.match(prompt, /redacted_pending_cloud_consent/);
  assert.doesNotMatch(prompt, /secret\.example\.test/);
  assert.doesNotMatch(prompt, /token=abc/);
  assert.match(prompt, /cloud_evidence_consent_required/);
});
