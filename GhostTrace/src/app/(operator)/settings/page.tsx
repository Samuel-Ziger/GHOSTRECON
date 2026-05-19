'use client';

import { useState } from 'react';
import { Save, KeyRound, Sparkles, ShieldCheck, Cloud, Layers } from 'lucide-react';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input, Field } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { useStore } from '@/lib/mock/store';
import { saveAIKeysToStorage } from '@/lib/storage/ai-keys';
import type { AIProviderId } from '@/lib/types';

const ICONS: Record<AIProviderId, any> = {
  anthropic: Sparkles,
  gemini: Cloud,
  openrouter: Layers
};

const HINTS: Record<AIProviderId, string> = {
  anthropic: 'sk-ant-api03-... · console.anthropic.com',
  gemini: 'AIza... · aistudio.google.com/app/apikey',
  openrouter: 'sk-or-v1-... · openrouter.ai/keys'
};

export default function SettingsPage() {
  const providers = useStore((s) => s.aiProviders);
  const upsert = useStore((s) => s.upsertAIProvider);

  const [drafts, setDrafts] = useState(() =>
    Object.fromEntries(providers.map((p) => [p.id, p]))
  );

  function update(id: AIProviderId, patch: Partial<typeof drafts[AIProviderId]>) {
    setDrafts((prev) => ({ ...prev, [id]: { ...prev[id], ...patch } }));
  }

  function save(id: AIProviderId) {
    const d = drafts[id];
    const next = { ...d, enabled: d.enabled ?? !!d.apiKey?.trim() };
    upsert(next);
    setDrafts((prev) => ({ ...prev, [id]: next }));
  }

  function saveAll() {
    const merged = providers.map((p) => drafts[p.id] ?? p);
    merged.forEach((p) =>
      upsert({ ...p, enabled: p.enabled ?? !!p.apiKey?.trim() })
    );
    saveAIKeysToStorage(merged);
  }

  return (
    <OperatorShell title="Configurações" breadcrumbs={[{ label: 'Configurações' }]}>
      <div className="px-6 py-6 max-w-3xl mx-auto space-y-5">
        <div className="p-4 rounded-md border border-accent/30 bg-accent-soft text-xs text-fg flex items-start gap-3">
          <ShieldCheck size={16} className="text-accent mt-0.5 shrink-0" />
          <div>
            <p className="font-medium">Onde ficam as API keys?</p>
            <p className="text-fg-muted mt-1">
              No protótipo, em <code className="font-mono text-fg">localStorage</code> do
              navegador. No backend FastAPI, em vault criptografado (KMS / Vault / SSM). Nunca em
              git, nunca em logs.
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles size={12} /> Provedores de IA
            </CardTitle>
            <Button variant="secondary" size="sm" onClick={saveAll}>
              <Save size={12} /> Salvar todos
            </Button>
          </CardHeader>
          <CardBody className="space-y-4">
            {providers.map((p) => {
              const Icon = ICONS[p.id];
              const d = drafts[p.id];
              return (
                <div
                  key={p.id}
                  className="p-4 rounded-md border border-border bg-surface-2 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded bg-surface-3 flex items-center justify-center text-fg-muted">
                        <Icon size={16} />
                      </div>
                      <div>
                        <div className="text-sm font-medium text-fg">{p.label}</div>
                        <div className="text-2xs font-mono text-fg-dim">
                          provider · {p.id}
                        </div>
                      </div>
                    </div>
                    {d.enabled ? (
                      <Badge mono tone="accent">
                        ATIVO
                      </Badge>
                    ) : (
                      <Badge mono>OFF</Badge>
                    )}
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <Field label="API key">
                      <div className="relative">
                        <KeyRound
                          size={13}
                          className="absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-dim"
                        />
                        <Input
                          type="password"
                          value={d.apiKey ?? ''}
                          onChange={(e) => update(p.id, { apiKey: e.target.value })}
                          placeholder={HINTS[p.id]}
                          className="pl-8 font-mono text-xs"
                        />
                      </div>
                    </Field>
                    <Field label="Model">
                      <Input
                        value={d.model ?? ''}
                        onChange={(e) => update(p.id, { model: e.target.value })}
                        className="font-mono text-xs"
                      />
                    </Field>
                    <Field label="Ativo">
                      <label className="flex items-center gap-2 h-9 text-xs text-fg-muted">
                        <input
                          type="checkbox"
                          checked={!!d.enabled}
                          onChange={(e) => update(p.id, { enabled: e.target.checked })}
                          className="accent-accent"
                        />
                        Habilitar este provider
                      </label>
                    </Field>
                  </div>
                  <div className="flex justify-end">
                    <Button variant="secondary" size="sm" onClick={() => save(p.id)}>
                      <Save size={12} /> Salvar
                    </Button>
                  </div>
                </div>
              );
            })}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Sobre</CardTitle>
          </CardHeader>
          <CardBody className="text-sm text-fg-muted space-y-2">
            <p>
              GhostTrace v0.1.0 — prototype build.
            </p>
            <p className="text-xs">
              Plataforma operacional ofensiva para Pentest, Red Team e Bug Bounty. Documenta a
              cadeia de ataque em tempo real e gera relatório enterprise-grade automaticamente.
            </p>
          </CardBody>
        </Card>
      </div>
    </OperatorShell>
  );
}
