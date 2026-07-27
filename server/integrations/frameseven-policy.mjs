/**
 * Perfis de ferramentas FrameSeven aprovados pelo GHOSTRECON.
 *
 * O perfil ofensivo continua intrusivo e exige todos os gates do RUN/Auto,
 * mas exclui ferramentas que extraem dados, tentam credenciais, provocam
 * rajadas ou confirmam execução de código. `-active-scan` permanece fora dos
 * dois perfis porque habilita probes com alteração de estado no FrameSeven.
 */
export const FRAMESEVEN_RECON_TOOLS_V1 = Object.freeze([
  'recon',
  'cve',
]);

export const FRAMESEVEN_OFFENSIVE_TOOLS_V1 = Object.freeze([
  'recon',
  'access',
  'redirect',
  'misconfig',
  'cve',
  'crawler',
  'content',
  'subdomain',
  'ports',
  'nmap',
  'bannergrab',
]);

export const FRAMESEVEN_RECON_TOOLS_ARG_V1 = FRAMESEVEN_RECON_TOOLS_V1.join(',');
export const FRAMESEVEN_OFFENSIVE_TOOLS_ARG_V1 = FRAMESEVEN_OFFENSIVE_TOOLS_V1.join(',');

const APPROVED_FRAMESEVEN_TOOL_PROFILES_V1 = new Map([
  [FRAMESEVEN_RECON_TOOLS_ARG_V1, Object.freeze({
    id: 'recon_v1',
    offensive: false,
    tools: FRAMESEVEN_RECON_TOOLS_ARG_V1,
  })],
  [FRAMESEVEN_OFFENSIVE_TOOLS_ARG_V1, Object.freeze({
    id: 'offensive_v1',
    offensive: true,
    tools: FRAMESEVEN_OFFENSIVE_TOOLS_ARG_V1,
  })],
]);

function invalidProfile(message) {
  const error = new Error(`Perfil FrameSeven inválido: ${message}`);
  error.code = 'FRAMESEVEN_TOOL_PROFILE_INVALID';
  return error;
}

export function resolveFrameSevenToolProfileV1(value = FRAMESEVEN_RECON_TOOLS_ARG_V1) {
  const requested = String(value || '').trim();
  if (!requested) throw invalidProfile('lista de ferramentas vazia');
  const parts = requested.split(',').map((part) => part.trim()).filter(Boolean);
  if (parts.length !== new Set(parts).size) {
    throw invalidProfile('ferramentas duplicadas');
  }
  const canonical = parts.join(',');
  const profile = APPROVED_FRAMESEVEN_TOOL_PROFILES_V1.get(canonical);
  if (!profile) {
    throw invalidProfile('use somente recon_v1 ou offensive_v1');
  }
  return profile;
}
