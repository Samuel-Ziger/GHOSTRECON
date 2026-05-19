'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { nanoid } from 'nanoid';
import {
  Save,
  Plus,
  Trash2,
  Image as ImageIcon,
  Terminal,
  ChevronRight
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input, Textarea, Field } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { RichEditor } from './rich-editor';
import { TriagePanel } from './triage-panel';
import { EnhanceButton } from '@/features/ai/enhance-button';
import type { TriageSuggestion } from '@/features/ai/tool-triage';
import { useStore } from '@/lib/mock/store';
import type {
  Vulnerability,
  Severity,
  VulnStatus,
  ReproStep,
  ProofOfConcept
} from '@/lib/types';
import { SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL } from '@/lib/utils/severity';

interface Props {
  projectId: string;
  initial?: Vulnerability;
}

const STATUSES: VulnStatus[] = ['unfixed', 'retest', 'fixed', 'wont_fix'];

function emptyStep(order: number): ReproStep {
  return { id: `st_${nanoid(6)}`, order, text: '', command: '', screenshots: [] };
}

function emptyPoc(): ProofOfConcept {
  return {
    id: `poc_${nanoid(6)}`,
    title: '',
    description: '',
    code: { lang: 'bash', content: '' },
    screenshots: []
  };
}

export function VulnEditor({ projectId, initial }: Props) {
  const router = useRouter();
  const upsert = useStore((s) => s.upsertVulnerability);

  const [v, setV] = useState<Vulnerability>(
    initial ??
      ({
        id: '',
        projectId,
        title: '',
        severity: 'medium' as Severity,
        status: 'unfixed',
        cwe: [],
        tags: [],
        targets: [],
        description: '',
        attackScenario: '',
        recommendation: '',
        steps: [emptyStep(1)],
        pocs: [],
        createdAt: '',
        updatedAt: ''
      } as Vulnerability)
  );

  function update<K extends keyof Vulnerability>(key: K, value: Vulnerability[K]) {
    setV((prev) => ({ ...prev, [key]: value }));
  }

  /**
   * Aplica uma sugestão de triagem ao formulário.
   * Substitui apenas os campos não-vazios da sugestão; preserva o que o
   * operador já tinha digitado nos demais.
   */
  function applyTriage(s: TriageSuggestion) {
    setV((prev) => {
      const mergedTargets = Array.from(new Set([...prev.targets, ...s.targets])).filter(Boolean);
      const mergedTags = Array.from(new Set([...prev.tags, ...s.tags])).filter(Boolean);
      const mergedCwe = Array.from(new Set([...prev.cwe, ...s.cwe])).filter(Boolean);

      return {
        ...prev,
        title: prev.title.trim() ? prev.title : s.title,
        severity: s.severity,
        cvss: s.cvss ?? prev.cvss,
        cwe: mergedCwe,
        tags: mergedTags,
        targets: mergedTargets,
        description:
          !prev.description || prev.description === '<p></p>'
            ? s.description
            : prev.description,
        // marca easily-exploitable se a tag estiver presente
        isEasilyExploitable:
          prev.isEasilyExploitable ||
          s.tags.some((t) => /easily-exploit/i.test(t))
      };
    });
  }

  function save() {
    const saved = upsert({ ...v, projectId });
    router.push(`/projects/${projectId}/vulnerabilities/${saved.id}`);
  }

  /* Steps */
  function addStep() {
    setV((p) => ({ ...p, steps: [...p.steps, emptyStep(p.steps.length + 1)] }));
  }
  function updateStep(id: string, patch: Partial<ReproStep>) {
    setV((p) => ({
      ...p,
      steps: p.steps.map((s) => (s.id === id ? { ...s, ...patch } : s))
    }));
  }
  function removeStep(id: string) {
    setV((p) => ({
      ...p,
      steps: p.steps.filter((s) => s.id !== id).map((s, i) => ({ ...s, order: i + 1 }))
    }));
  }

  /* POCs */
  function addPoc() {
    setV((p) => ({ ...p, pocs: [...p.pocs, emptyPoc()] }));
  }
  function updatePoc(id: string, patch: Partial<ProofOfConcept>) {
    setV((p) => ({
      ...p,
      pocs: p.pocs.map((c) => (c.id === id ? { ...c, ...patch } : c))
    }));
  }
  function removePoc(id: string) {
    setV((p) => ({ ...p, pocs: p.pocs.filter((c) => c.id !== id) }));
  }

  return (
    <div className="px-6 py-6 max-w-5xl mx-auto space-y-5">
      {/* Triagem por IA — entrada de saída crua que auto-preenche o formulário */}
      <TriagePanel onApply={applyTriage} />

      {/* Title + severity row */}
      <Card>
        <CardBody className="space-y-4">
          <Field label="Título" required>
            <Input
              required
              value={v.title}
              onChange={(e) => update('title', e.target.value)}
              placeholder="ex.: Blind Command Injection em search.php"
              className="text-base h-11"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Field label="Severidade" required>
              <div className="grid grid-cols-5 gap-1">
                {SEVERITY_ORDER.map((s) => (
                  <button
                    type="button"
                    key={s}
                    onClick={() => update('severity', s)}
                    className={`px-1 py-2 text-2xs font-mono uppercase rounded border transition-all ${
                      v.severity === s
                        ? 'border-current'
                        : 'border-border text-fg-muted hover:border-border-strong'
                    }`}
                    style={
                      v.severity === s
                        ? {
                            color: `var(--sev-${s})`,
                            background: `var(--sev-${s})20`
                          }
                        : undefined
                    }
                  >
                    {SEVERITY_LABEL[s][0]}
                  </button>
                ))}
              </div>
              <div className="mt-2">
                <SeverityBadge severity={v.severity} size="sm" />
              </div>
            </Field>

            <Field label="Status">
              <select
                value={v.status}
                onChange={(e) => update('status', e.target.value as VulnStatus)}
                className="w-full h-9 px-3 text-sm bg-surface-2 border border-border rounded-md text-fg"
              >
                {STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {STATUS_LABEL[s]}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="CVSS v3.1 Score">
              <Input
                value={v.cvss?.score ?? ''}
                onChange={(e) =>
                  update('cvss', {
                    vector: v.cvss?.vector ?? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    score: Number(e.target.value) || 0
                  })
                }
                placeholder="9.8"
                type="number"
                step="0.1"
                min="0"
                max="10"
                className="font-mono"
              />
            </Field>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Field label="CVSS Vector">
              <Input
                value={v.cvss?.vector ?? ''}
                onChange={(e) =>
                  update('cvss', {
                    vector: e.target.value,
                    score: v.cvss?.score ?? 0
                  })
                }
                placeholder="CVSS:3.1/AV:N/AC:L/..."
                className="font-mono text-xs"
              />
            </Field>
            <Field label="CWE">
              <Input
                value={v.cwe.join(', ')}
                onChange={(e) =>
                  update(
                    'cwe',
                    e.target.value
                      .split(',')
                      .map((s) => s.trim())
                      .filter(Boolean)
                  )
                }
                placeholder="CWE-78, CWE-77"
                className="font-mono text-xs"
              />
            </Field>
            <Field label="Tags">
              <Input
                value={v.tags.join(', ')}
                onChange={(e) =>
                  update(
                    'tags',
                    e.target.value
                      .split(',')
                      .map((s) => s.trim())
                      .filter(Boolean)
                  )
                }
                placeholder="RCE, OWASP-A03, Easily-Exploitable"
                className="text-xs"
              />
            </Field>
          </div>

          <Field label="Ativos afetados" hint="um por linha" required>
            <Textarea
              required
              rows={2}
              value={v.targets.join('\n')}
              onChange={(e) =>
                update('targets', e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))
              }
              placeholder={'stock.locbook.io\n3.212.54.4'}
              className="font-mono text-sm"
            />
          </Field>

          <div className="flex items-center gap-4 pt-1">
            <label className="flex items-center gap-2 text-xs text-fg-muted cursor-pointer">
              <input
                type="checkbox"
                checked={!!v.isZeroDay}
                onChange={(e) => update('isZeroDay', e.target.checked)}
                className="accent-accent"
              />
              <Badge mono>Zero-Day</Badge>
            </label>
            <label className="flex items-center gap-2 text-xs text-fg-muted cursor-pointer">
              <input
                type="checkbox"
                checked={!!v.isEasilyExploitable}
                onChange={(e) => update('isEasilyExploitable', e.target.checked)}
                className="accent-accent"
              />
              <Badge mono>Easily-Exploitable</Badge>
            </label>
          </div>
        </CardBody>
      </Card>

      {/* Long-form fields */}
      {(
        [
          { key: 'description', label: 'Descrição', placeholder: 'O que é, onde está, como funciona.' },
          { key: 'attackScenario', label: 'Cenário de ataque', placeholder: 'Como um atacante exploraria; impacto combinado.' },
          { key: 'recommendation', label: 'Recomendação', placeholder: 'Ações concretas: imediatas, configuração, código, processo.' },
          { key: 'remediationNotes', label: 'Notas de remediação', placeholder: 'Status do fix, prazos, contexto operacional.' },
          { key: 'additionalNotes', label: 'Notas adicionais', placeholder: 'Observações livres, IOCs, links internos.' }
        ] as const
      ).map((f) => (
        <Card key={f.key}>
          <CardHeader>
            <CardTitle>{f.label}</CardTitle>
            {(f.key === 'description' ||
              f.key === 'attackScenario' ||
              f.key === 'recommendation' ||
              f.key === 'remediationNotes') && (
              <EnhanceButton
                field={f.key}
                currentValue={(v[f.key] as string) ?? ''}
                vuln={{
                  title: v.title,
                  severity: v.severity,
                  cwe: v.cwe,
                  tags: v.tags,
                  targets: v.targets
                }}
                onApply={(val) => update(f.key, val)}
              />
            )}
          </CardHeader>
          <CardBody>
            <RichEditor
              value={(v[f.key] as string) ?? ''}
              onChange={(val) => update(f.key as any, val as any)}
              placeholder={f.placeholder}
            />
          </CardBody>
        </Card>
      ))}

      {/* Steps to Reproduce */}
      <Card>
        <CardHeader>
          <CardTitle>Passos de reprodução</CardTitle>
          <Button type="button" variant="ghost" size="sm" onClick={addStep}>
            <Plus size={12} /> Adicionar passo
          </Button>
        </CardHeader>
        <CardBody className="space-y-3">
          {v.steps.map((step) => (
            <div
              key={step.id}
              className="flex gap-3 items-start p-3 rounded-md border border-border bg-bg/40"
            >
              <div className="shrink-0 w-7 h-7 rounded font-mono text-xs flex items-center justify-center bg-surface-3 text-fg-muted border border-border">
                {step.order}
              </div>
              <div className="flex-1 space-y-2 min-w-0">
                <Input
                  value={step.text}
                  onChange={(e) => updateStep(step.id, { text: e.target.value })}
                  placeholder="Descrição do passo"
                  className="border-0 bg-transparent h-7 px-0 focus-visible:shadow-none"
                />
                <div className="flex items-start gap-2">
                  <Terminal size={12} className="mt-2 text-fg-dim shrink-0" />
                  <Textarea
                    value={step.command ?? ''}
                    onChange={(e) => updateStep(step.id, { command: e.target.value })}
                    placeholder="comando ou payload (opcional)"
                    rows={2}
                    className="font-mono text-xs bg-bg"
                  />
                </div>
                <button
                  type="button"
                  className="text-2xs text-fg-dim hover:text-fg-muted flex items-center gap-1"
                >
                  <ImageIcon size={11} /> Adicionar screenshot
                </button>
              </div>
              <button
                type="button"
                onClick={() => removeStep(step.id)}
                className="text-fg-dim hover:text-[var(--sev-critical)] p-1"
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* Proof of Concept */}
      <Card>
        <CardHeader>
          <CardTitle>Proof of concept</CardTitle>
          <Button type="button" variant="ghost" size="sm" onClick={addPoc}>
            <Plus size={12} /> Adicionar POC
          </Button>
        </CardHeader>
        <CardBody className="space-y-3">
          {v.pocs.length === 0 && (
            <p className="text-xs text-fg-dim text-center py-4">
              Nenhuma POC adicionada. Cole shell, código de exploit ou requisição.
            </p>
          )}
          {v.pocs.map((poc) => (
            <div
              key={poc.id}
              className="p-3 rounded-md border border-border bg-bg/40 space-y-2"
            >
              <div className="flex items-center gap-2">
                <Input
                  value={poc.title}
                  onChange={(e) => updatePoc(poc.id, { title: e.target.value })}
                  placeholder="Título da POC"
                  className="h-8"
                />
                <button
                  type="button"
                  onClick={() => removePoc(poc.id)}
                  className="text-fg-dim hover:text-[var(--sev-critical)] p-1"
                >
                  <Trash2 size={14} />
                </button>
              </div>
              <Input
                value={poc.description ?? ''}
                onChange={(e) => updatePoc(poc.id, { description: e.target.value })}
                placeholder="Breve descrição"
                className="h-8 text-xs"
              />
              <div className="flex items-center gap-2">
                <select
                  value={poc.code?.lang ?? 'bash'}
                  onChange={(e) =>
                    updatePoc(poc.id, {
                      code: { lang: e.target.value, content: poc.code?.content ?? '' }
                    })
                  }
                  className="h-7 px-2 text-xs bg-surface-2 border border-border rounded text-fg-muted font-mono"
                >
                  {['bash', 'python', 'http', 'sql', 'js', 'php', 'text'].map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
                <span className="text-2xs text-fg-dim font-mono">code · monospaced</span>
              </div>
              <Textarea
                value={poc.code?.content ?? ''}
                onChange={(e) =>
                  updatePoc(poc.id, {
                    code: { lang: poc.code?.lang ?? 'bash', content: e.target.value }
                  })
                }
                rows={5}
                placeholder="$ id\nuid=33(www-data) gid=33(www-data)..."
                className="font-mono text-xs bg-bg"
              />
              <button
                type="button"
                className="text-2xs text-fg-dim hover:text-fg-muted flex items-center gap-1"
              >
                <ImageIcon size={11} /> Adicionar screenshot
              </button>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* Save */}
      <div className="flex items-center justify-between pt-2">
        <p className="text-xs text-fg-dim flex items-center gap-1">
          <ChevronRight size={12} /> Autosave indisponível no protótipo — clique em salvar.
        </p>
        <Button variant="primary" size="md" onClick={save} disabled={!v.title}>
          <Save size={14} /> Salvar vulnerabilidade
        </Button>
      </div>
    </div>
  );
}
