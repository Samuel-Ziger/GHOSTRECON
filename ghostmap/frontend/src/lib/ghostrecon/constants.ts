export const MITRE_LIVE_SESSION_STORAGE_KEY = 'ghostrecon_mitre_live_session_id';
export const REPORTE_PAYLOAD_KEY = 'ghostrecon_reporte_payload';
export const REPORTE_PAYLOAD_SHARED_KEY = 'ghostrecon_reporte_payload_shared';

export function mitreChannelName(sessionId: string): string {
  return `ghostrecon-mitre-${sessionId}`;
}
