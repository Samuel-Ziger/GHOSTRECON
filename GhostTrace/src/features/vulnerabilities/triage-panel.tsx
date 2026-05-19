'use client';

import { useState } from 'react';
import {
  Sparkles,
  Loader2,
  Wand2,
  ChevronDown,
  ChevronRight,
  Check,
  Terminal,
  AlertCircle
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import {
  triageToolOutput,
  TOOL_LABEL,
  type TriageSuggestion
} from '@/features/ai/tool-triage';
import { useStore } from '@/lib/mock/store';

interface Props {
  onApply: (suggestion: TriageSuggestion) => void;
}

const SAMPLES: { label: string; payload: string }[] = [
  {
    label: 'sqlmap',
    payload: `[17:26:17] [INFO] resuming back-end DBMS 'mysql'
sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 6866=6866

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 1974 FROM (SELECT(SLEEP(5)))IsxZ2)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-3000 UNION ALL SELECT NULL,NULL,CONCAT(0x7176767a71,...)
---
back-end DBMS: MySQL >= 5.0.12
[17:26:18] [INFO] testing connection to the target URL`
  },
  {
    label: 'nmap',
    payload: `Starting Nmap 7.94 ( https://nmap.org ) at 2026-05-11 08:05 -03
Nmap scan report for ec2-3-212-54-4.compute-1.amazonaws.com (3.212.54.4)
Host is up (0.012s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))

Service detection performed. Please report any incorrect results.
Nmap done: 1 IP address (1 host up) scanned in 23.42 seconds`
  },
  {
    label: 'nuclei',
    payload: `[CVE-2024-23897] [http] [critical] https://target.com/api/jenkins
[exposed-panels:apache-tomcat-manager] [http] [medium] https://10.100.85.100:8080/manager/html
[http-missing-security-headers:strict-transport-security] [info] https://target.com/`
  }
];

export function TriagePanel({ onApply }: Props) {
  const [raw, setRaw] = useState('');
  const [loading, setLoading] = useState(false);
  const [suggestion, setSuggestion] = useState<TriageSuggestion | null>(null);
  const [showHighlights, setShowHighlights] = useState(false);
  const [applied, setApplied] = useState(false);

  const providers = useStore((s) => s.aiProviders);
  const activeProvider = providers.find((p) => p.enabled);

  async function analyze() {
    if (!raw.trim()) return;
    setLoading(true);
    setApplied(false);
    try {
      const s = await triageToolOutput(raw);
      setSuggestion(s);
    } finally {
      setLoading(false);
    }
  }

  function apply() {
    if (!suggestion) return;
    onApply(suggestion);
    setApplied(true);
  }

  function loadSample(payload: string) {
    setRaw(payload);
    setSuggestion(null);
    setApplied(false);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Wand2 size={12} className="text-accent" /> Triagem por IA · Auto-preenchimento
        </CardTitle>
        <Badge mono tone={activeProvider ? 'accent' : 'muted'}>
          {activeProvider ? `${activeProvider.label.toUpperCase()} · ATIVO` : 'PROVIDER OFF · USANDO MOCK LOCAL'}
        </Badge>
      </CardHeader>
      <CardBody className="space-y-3">
        <p className="text-xs text-fg-muted leading-relaxed">
          Cole a saída crua de uma ferramenta — <span className="font-mono text-fg">nmap</span>,{' '}
          <span className="font-mono text-fg">sqlmap</span>,{' '}
          <span className="font-mono text-fg">nuclei</span>,{' '}
          <span className="font-mono text-fg">linpeas</span>,{' '}
          <span className="font-mono text-fg">ffuf</span>,{' '}
          <span className="font-mono text-fg">curl</span> com payload de LFI/SSRF/RCE, etc. A IA
          detecta o tipo, classifica severidade, atribui CVSS/CWE e gera a descrição técnica.
          Você revisa e ajusta antes de salvar.
        </p>

        {/* sample chips */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-2xs uppercase tracking-wider text-fg-dim font-mono mr-1">
            samples:
          </span>
          {SAMPLES.map((s) => (
            <button
              key={s.label}
              type="button"
              onClick={() => loadSample(s.payload)}
              className="text-2xs font-mono uppercase px-2 py-0.5 rounded border border-border bg-surface-2 hover:bg-surface-3 hover:border-border-strong text-fg-muted hover:text-fg transition-colors"
            >
              {s.label}
            </button>
          ))}
        </div>

        <div className="relative">
          <Terminal
            size={13}
            className="absolute left-3 top-3 text-fg-dim pointer-events-none"
          />
          <Textarea
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              if (suggestion) setSuggestion(null);
            }}
            placeholder="$ nmap -sV -p- 3.212.54.4
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
..."
            rows={9}
            className="font-mono text-xs bg-bg pl-8 leading-relaxed"
          />
          {raw && (
            <span className="absolute right-3 bottom-2 text-2xs font-mono text-fg-dim">
              {raw.length} chars · {raw.split('\n').length} linhas
            </span>
          )}
        </div>

        <div className="flex items-center justify-between gap-2">
          <p className="text-2xs text-fg-dim">
            {activeProvider ? (
              <>
                Será enviado ao provider <span className="text-fg">{activeProvider.label}</span>.
              </>
            ) : (
              <>
                Nenhum provider configurado — usando engine local de pattern-matching para demo.
                Configure um provider em <span className="text-fg">Configurações</span> para
                inferência real.
              </>
            )}
          </p>
          <div className="flex items-center gap-2">
            {raw && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  setRaw('');
                  setSuggestion(null);
                  setApplied(false);
                }}
              >
                Limpar
              </Button>
            )}
            <Button
              type="button"
              variant="primary"
              size="md"
              onClick={analyze}
              disabled={!raw.trim() || loading}
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" /> Analisando...
                </>
              ) : (
                <>
                  <Sparkles size={14} /> Analisar com IA
                </>
              )}
            </Button>
          </div>
        </div>

        <AnimatePresence>
          {suggestion && !loading && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.18, ease: [0.2, 0.8, 0.2, 1] }}
              className="rounded-md border border-accent/30 bg-accent-soft p-4 space-y-3"
            >
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="space-y-1.5 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge mono tone="accent">
                      DETECTADO: {TOOL_LABEL[suggestion.tool].toUpperCase()}
                    </Badge>
                    <SeverityBadge severity={suggestion.severity} size="sm" />
                    {suggestion.cvss && (
                      <Badge mono>
                        CVSS {suggestion.cvss.score.toFixed(1)}
                      </Badge>
                    )}
                    <ConfidenceBar value={suggestion.confidence} />
                  </div>
                  <p className="text-sm font-medium text-fg leading-snug">
                    {suggestion.title || '(sem título sugerido)'}
                  </p>
                </div>
                <Button
                  type="button"
                  variant="primary"
                  size="md"
                  onClick={apply}
                  disabled={applied}
                >
                  {applied ? (
                    <>
                      <Check size={14} /> Aplicado
                    </>
                  ) : (
                    <>
                      <Sparkles size={14} /> Aplicar ao formulário
                    </>
                  )}
                </Button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-accent/20 text-xs">
                <Pair label="Severidade">
                  <span className="text-fg">{suggestion.severity.toUpperCase()}</span>
                  <p className="text-fg-muted text-2xs mt-0.5 leading-snug">
                    {suggestion.severityRationale}
                  </p>
                </Pair>
                <Pair label="CVSS v3.1">
                  {suggestion.cvss ? (
                    <>
                      <span className="font-mono text-fg">{suggestion.cvss.score.toFixed(1)}</span>
                      <p className="font-mono text-2xs text-fg-muted mt-0.5 break-all">
                        {suggestion.cvss.vector}
                      </p>
                    </>
                  ) : (
                    <span className="text-fg-dim">— não atribuído (severidade info)</span>
                  )}
                </Pair>
                <Pair label="CWE">
                  {suggestion.cwe.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {suggestion.cwe.map((c) => (
                        <Badge key={c} mono>
                          {c}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-fg-dim">— nenhum</span>
                  )}
                </Pair>
                <Pair label="Tags">
                  <div className="flex flex-wrap gap-1">
                    {suggestion.tags.slice(0, 6).map((t) => (
                      <Badge key={t} mono>
                        {t}
                      </Badge>
                    ))}
                  </div>
                </Pair>
                {suggestion.targets.length > 0 && (
                  <Pair label="Alvos extraídos" className="sm:col-span-2">
                    <div className="flex flex-wrap gap-1.5 font-mono text-xs text-fg">
                      {suggestion.targets.map((t) => (
                        <span key={t} className="px-1.5 py-0.5 bg-surface-2 rounded border border-border">
                          {t}
                        </span>
                      ))}
                    </div>
                  </Pair>
                )}
                <Pair label="Descrição gerada" className="sm:col-span-2">
                  <div
                    className="text-fg leading-relaxed prose-styles text-sm"
                    dangerouslySetInnerHTML={{ __html: suggestion.description }}
                  />
                </Pair>
              </div>

              {suggestion.rawHighlights && suggestion.rawHighlights.length > 0 && (
                <div className="pt-2 border-t border-accent/20">
                  <button
                    type="button"
                    onClick={() => setShowHighlights((v) => !v)}
                    className="flex items-center gap-1.5 text-2xs uppercase tracking-wider text-fg-muted hover:text-fg font-mono"
                  >
                    {showHighlights ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    linhas-chave que sustentam a triagem ({suggestion.rawHighlights.length})
                  </button>
                  <AnimatePresence>
                    {showHighlights && (
                      <motion.pre
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="mt-2 text-2xs font-mono bg-bg border border-border rounded p-2 overflow-x-auto text-fg-muted whitespace-pre"
                      >
                        {suggestion.rawHighlights.join('\n')}
                      </motion.pre>
                    )}
                  </AnimatePresence>
                </div>
              )}

              {suggestion.confidence < 0.5 && (
                <div className="flex items-start gap-2 text-2xs text-[var(--sev-medium)] bg-[var(--sev-medium)]/10 border border-[var(--sev-medium)]/30 rounded p-2">
                  <AlertCircle size={13} className="shrink-0 mt-0.5" />
                  <span>
                    Baixa confiança na detecção — revise cuidadosamente todos os campos antes de
                    salvar. O motor não reconheceu o formato da ferramenta.
                  </span>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </CardBody>
    </Card>
  );
}

function Pair({
  label,
  children,
  className
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      <div className="text-2xs uppercase tracking-wider text-fg-dim font-mono mb-1">{label}</div>
      <div>{children}</div>
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    value >= 0.8
      ? 'var(--sev-low)'
      : value >= 0.5
      ? 'var(--sev-medium)'
      : 'var(--sev-high)';
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1 bg-surface-2 rounded-full overflow-hidden border border-border">
        <div
          className="h-full transition-all"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
      <span className="text-2xs font-mono" style={{ color }}>
        {pct}%
      </span>
    </div>
  );
}
