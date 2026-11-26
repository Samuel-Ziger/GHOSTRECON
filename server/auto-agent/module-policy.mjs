export function catalogModuleRiskClass(module = {}) {
  const declared = String(module.class || module.manifest?.class || '').trim().toLowerCase();
  if (declared === 'destructive' || module.manifest?.destructive === true) return 'destructive';
  if (declared === 'intrusive' || module.manifest?.intrusive === true) return 'intrusive';
  if (declared === 'active') return 'active';
  if (declared === 'deep_passive') return 'deep_passive';
  if (declared === 'passive' || declared === 'hexstrike_intel') return 'passive';
  return 'unknown';
}

export function isCatalogModuleAllowed(module, {
  allowIntrusive = false,
  autonomyLevel = 'observation',
} = {}) {
  if (!module || module.available === false) return false;
  const riskClass = catalogModuleRiskClass(module);
  if (riskClass === 'destructive' || riskClass === 'unknown') return false;
  if (autonomyLevel === 'observation') {
    return riskClass === 'passive' || riskClass === 'deep_passive';
  }
  if (autonomyLevel === 'assisted') {
    return ['passive', 'deep_passive', 'active'].includes(riskClass);
  }
  if (['authorized', 'authorized_opsec'].includes(autonomyLevel)) {
    return ['passive', 'deep_passive', 'active'].includes(riskClass)
      || (riskClass === 'intrusive' && allowIntrusive === true);
  }
  return false;
}

export function availableCatalogIds(catalog, options = {}) {
  return (catalog?.modules || [])
    .filter((module) => isCatalogModuleAllowed(module, options))
    .map((module) => module.id);
}
