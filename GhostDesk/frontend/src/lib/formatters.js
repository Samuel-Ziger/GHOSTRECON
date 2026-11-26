const SEVERITY_CLASS = Object.freeze({
  critical: 'sev-critical',
  high: 'sev-high',
  med: 'sev-medium',
  medium: 'sev-medium',
  low: 'sev-low',
  info: 'sev-info',
})

const SEVERITY_COLOR = Object.freeze({
  critical: '#ff3366',
  high: '#ff8a3d',
  med: '#ffd23d',
  medium: '#ffd23d',
  low: '#3dd6a8',
  info: '#5a9bd4',
})

export function badgeClass(priority) {
  return SEVERITY_CLASS[String(priority || '').toLowerCase()] || 'sev-info'
}

export function severityColor(priority) {
  return SEVERITY_COLOR[String(priority || '').toLowerCase()] || '#5a9bd4'
}

export function formatDate(value) {
  return value ? new Date(value).toLocaleString() : '—'
}

export function shortScanId(id) {
  const value = String(id || '')
  if (value.startsWith('scope:')) {
    return value.replace(/^scope:([^:]+):(\d+)$/, (_, project, number) => `${decodeURIComponent(project)} #${number}`)
  }
  if (value.includes(':')) return value.split(':').slice(-2).join(':')
  return `#${value}`
}
