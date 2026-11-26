import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeHashRoute, ROUTES } from '../src/router/hash-router.js'
import { badgeClass, formatDate, severityColor, shortScanId } from '../src/lib/formatters.js'

test('rotas hash preservam as cinco telas e fazem fallback seguro', () => {
  assert.deepEqual(
    ROUTES.map((route) => route.path),
    ['/dashboard', '/scans', '/projects', '/clients', '/intel'],
  )
  assert.equal(normalizeHashRoute('#/scans'), '/scans')
  assert.equal(normalizeHashRoute('/intel'), '/intel')
  assert.equal(normalizeHashRoute('#/desconhecida'), '/dashboard')
})

test('formatadores preservam severidade, datas vazias e IDs de scan', () => {
  assert.equal(badgeClass('HIGH'), 'sev-high')
  assert.equal(badgeClass('med'), 'sev-medium')
  assert.equal(badgeClass('outra'), 'sev-info')
  assert.equal(severityColor('critical'), '#ff3366')
  assert.equal(formatDate(null), '—')
  assert.equal(shortScanId('scope:cliente%20x:42'), 'cliente x #42')
  assert.equal(shortScanId('sqlite:run:9'), 'run:9')
  assert.equal(shortScanId(7), '#7')
})
