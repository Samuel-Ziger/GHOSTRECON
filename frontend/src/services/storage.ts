export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export const STORAGE_KEYS = Object.freeze({
  apiBase: 'ghostrecon_api_base',
  auth: 'ghostrecon_auth_json',
  profile: 'ghostrecon_profile',
  dismissedFingerprints: 'ghostrecon_dismissed_fps',
  autoSession: 'ghostrecon.auto.lastSessionId',
  mitreSession: 'ghostrecon_mitre_live_session_id',
  reportPayload: 'ghostrecon_reporte_payload',
  reportPayloadShared: 'ghostrecon_reporte_payload_shared',
  vigoliumProfile: 'ghostrecon_vigolium_run_profile',
});

export function safeRead(storage: StorageLike | null | undefined, key: string): string | null {
  try {
    return storage?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

export function safeWrite(
  storage: StorageLike | null | undefined,
  key: string,
  value: string | null | undefined,
): boolean {
  try {
    if (!storage) return false;
    if (value == null || value === '') storage.removeItem(key);
    else storage.setItem(key, String(value));
    return true;
  } catch {
    return false;
  }
}

export function readJson<T>(
  storage: StorageLike | null | undefined,
  key: string,
  fallback: T,
): T {
  const raw = safeRead(storage, key);
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function writeJson(
  storage: StorageLike | null | undefined,
  key: string,
  value: unknown,
): boolean {
  try {
    return safeWrite(storage, key, JSON.stringify(value));
  } catch {
    return false;
  }
}
