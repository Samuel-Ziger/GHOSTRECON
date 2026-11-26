export type TunnelValidation = {
  direct?: { code?: unknown; ip?: unknown; ok?: unknown };
  ok?: unknown;
  status?: { active?: unknown; openvpn?: unknown; tor?: unknown };
  tor?: { code?: unknown; ip?: unknown; isTor?: unknown; ok?: unknown };
  validated?: unknown;
};

export type TunnelValidationView = {
  direct: string;
  directOk: boolean;
  services: string;
  servicesOk: boolean;
  summary: string;
  tor: string;
  torOk: boolean;
  validated: boolean;
};

export function tunnelApiUrl(pathname: string, protocol = 'http:'): string {
  const path = pathname.startsWith('/') ? pathname : `/${pathname}`;
  return ['file:', 'blob:'].includes(protocol)
    ? `http://127.0.0.1:3847${path}`
    : path;
}

export function formatTunnelValidation(data: TunnelValidation): TunnelValidationView {
  const status = data.status || {};
  const direct = data.direct || {};
  const tor = data.tor || {};
  const servicesOk = Boolean(status.active);
  const directOk = Boolean(direct.ok);
  const torOk = Boolean(tor.isTor);
  const validated = Boolean(data.validated);
  return {
    services: `active=${servicesOk} • tor=${String(status.tor || 'unknown')} • openvpn=${String(status.openvpn || 'unknown')}`,
    servicesOk,
    direct: `ok=${directOk} • ip=${String(direct.ip || 'n/a')} • code=${String(direct.code ?? '')}`,
    directOk,
    tor: `ok=${Boolean(tor.ok)} • isTor=${torOk} • ip=${String(tor.ip || 'n/a')} • code=${String(tor.code ?? '')}`,
    torOk,
    validated,
    summary: validated
      ? 'VALIDADO: tráfego via Tor ativo.'
      : 'NÃO VALIDADO: túnel/Tor não confirmado.',
  };
}
