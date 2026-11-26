import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactUiPage } from '../../../page-registry';
import { useNativePageDocument } from '../native-page-shell';
import {
  formatTunnelValidation,
  tunnelApiUrl,
  type TunnelValidation,
  type TunnelValidationView,
} from './model';

const EMPTY_VIEW: TunnelValidationView = {
  direct: '—', directOk: false,
  services: '—', servicesOk: false,
  summary: 'Aguardando validação…',
  tor: '—', torOk: false,
  validated: false,
};

export function TorValidatorPage({ page }: { page: ReactUiPage }) {
  useNativePageDocument(page, 'tor-validator');
  const mounted = useRef(true);
  const [view, setView] = useState(EMPTY_VIEW);
  const [auto, setAuto] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const validate = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(tunnelApiUrl('/api/tunnel/validate', window.location.protocol), { signal });
      const data = await response.json().catch(() => ({})) as TunnelValidation & { error?: unknown };
      if (!response.ok || data.ok === false) {
        throw new Error(String(data.error || `HTTP ${response.status}`));
      }
      if (mounted.current) setView(formatTunnelValidation(data));
    } catch (cause) {
      if (signal?.aborted) return;
      if (mounted.current) setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    void validate(controller.signal);
    return () => {
      mounted.current = false;
      controller.abort();
    };
  }, [validate]);

  useEffect(() => {
    if (!auto) return undefined;
    const timer = window.setInterval(() => void validate(), 12_000);
    return () => window.clearInterval(timer);
  }, [auto, validate]);

  const summaryText = error ? `Erro na validação: ${error}` : view.summary;
  const summaryClass = error ? 'bad' : view.validated ? 'ok' : view === EMPTY_VIEW ? 'dim' : 'bad';

  return (
    <div className="wrap">
      <h2>Tor Validator</h2>
      <p className="dim">Valida status de túnel e saída real via Tor.</p>
      <div style={{ display: 'flex', gap: 8, margin: '10px 0 16px' }}>
        <button type="button" disabled={loading} onClick={() => void validate()}>
          {loading ? 'Validando…' : 'Validar agora'}
        </button>
        <button type="button" id="autoBtn" aria-pressed={auto} onClick={() => setAuto((value) => !value)}>
          Auto: {auto ? 'ON' : 'OFF'}
        </button>
      </div>
      <div className={`card ${summaryClass}`} id="summary">{summaryText}</div>
      <div className="card">
        <div><strong>Status serviços</strong></div>
        <div id="svc" className={view.servicesOk ? 'ok' : 'bad'}>{view.services}</div>
      </div>
      <div className="card">
        <div><strong>IP direto</strong></div>
        <div id="direct" className={view.directOk ? 'ok' : 'bad'}>{view.direct}</div>
      </div>
      <div className="card">
        <div><strong>IP via Tor</strong></div>
        <div id="tor" className={view.torOk ? 'ok' : 'bad'}>{view.tor}</div>
      </div>
    </div>
  );
}
