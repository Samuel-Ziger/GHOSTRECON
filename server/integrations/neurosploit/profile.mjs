export async function validateNeuroSploitProfileReady(artexClient, profile) {
  if (!profile) throw new Error('perfil GhostIA/Artex não encontrado');
  if (!String(profile.model || '').trim()) throw new Error('perfil GhostIA/Artex sem modelo configurado');
  if (String(profile.format || '') === 'chatgpt-plan') {
    const plan = await artexClient.chatGptPlanStatus();
    if (plan?.connected !== true) throw new Error('perfil Codex desconectado; conecte o ChatGPT Plan no GhostIA');
    return profile;
  }
  if (!String(profile.api_key_hint || '').trim()) {
    throw new Error('perfil de API sem credencial; configure a chave no GhostIA');
  }
  return profile;
}

export async function resolveNeuroSploitProfile(artexClient, profileId) {
  const id = Number(profileId);
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error('perfil GhostIA/Artex obrigatório');
  const profilesBody = await artexClient.listProfiles();
  const profile = (profilesBody?.profiles || []).find((item) => Number(item.id) === id);
  return validateNeuroSploitProfileReady(artexClient, profile);
}
