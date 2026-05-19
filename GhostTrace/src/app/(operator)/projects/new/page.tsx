'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ChevronLeft } from 'lucide-react';
import Link from 'next/link';
import { OperatorShell } from '@/components/layout/operator-shell';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input, Textarea, Field } from '@/components/ui/input';
import { useStore } from '@/lib/mock/store';
import type { Methodology, EngagementType } from '@/lib/types';

const METHODOLOGIES: { value: Methodology; label: string; hint: string }[] = [
  { value: 'blackbox', label: 'Black Box', hint: 'sem informações prévias' },
  { value: 'graybox', label: 'Gray Box', hint: 'acesso parcial / credenciais' },
  { value: 'whitebox', label: 'White Box', hint: 'acesso total / código' }
];

const ENGAGEMENT_TYPES: { value: EngagementType; label: string }[] = [
  { value: 'web_app', label: 'Web Application' },
  { value: 'network_internal', label: 'Network — Internal' },
  { value: 'network_external', label: 'Network — External' },
  { value: 'red_team', label: 'Red Team' },
  { value: 'mobile', label: 'Mobile' },
  { value: 'cloud', label: 'Cloud' },
  { value: 'bug_bounty', label: 'Bug Bounty' }
];

export default function NewProjectPage() {
  const router = useRouter();
  const upsert = useStore((s) => s.upsertProject);

  const [client, setClient] = useState('');
  const [codename, setCodename] = useState('');
  const [scope, setScope] = useState('');
  const [methodology, setMethodology] = useState<Methodology>('graybox');
  const [engagementType, setEngagementType] = useState<EngagementType>('web_app');
  const [startDate, setStartDate] = useState(new Date().toISOString().slice(0, 10));
  const [notes, setNotes] = useState('');

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const proj = upsert({
      client,
      codename: codename || undefined,
      scope: scope.split('\n').map((s) => s.trim()).filter(Boolean),
      methodology,
      engagementType,
      startDate,
      notes: notes || undefined
    });
    router.push(`/projects/${proj.id}`);
  }

  return (
    <OperatorShell
      title="Novo projeto"
      breadcrumbs={[{ label: 'Projetos' }, { label: 'Novo' }]}
      actions={
        <Link href="/projects">
          <Button variant="ghost" size="md">
            <ChevronLeft size={14} />
            Cancelar
          </Button>
        </Link>
      }
    >
      <form onSubmit={submit} className="px-6 py-6 max-w-3xl mx-auto space-y-4">
        <Card>
          <div className="p-5 space-y-4">
            <h2 className="text-xs font-medium uppercase tracking-wider text-accent">
              Identificação
            </h2>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Cliente" required>
                <Input
                  required
                  value={client}
                  onChange={(e) => setClient(e.target.value)}
                  placeholder="ex.: Acme Corp"
                />
              </Field>
              <Field label="Codinome (opcional)" hint="usado em chats e logs">
                <Input
                  value={codename}
                  onChange={(e) => setCodename(e.target.value)}
                  placeholder="ex.: OPERATION_NIGHTFALL"
                />
              </Field>
            </div>
          </div>
        </Card>

        <Card>
          <div className="p-5 space-y-4">
            <h2 className="text-xs font-medium uppercase tracking-wider text-accent">
              Engajamento
            </h2>
            <Field label="Tipo">
              <div className="grid grid-cols-3 sm:grid-cols-4 gap-2">
                {ENGAGEMENT_TYPES.map((t) => (
                  <button
                    type="button"
                    key={t.value}
                    onClick={() => setEngagementType(t.value)}
                    className={`px-3 py-2 text-xs rounded border transition-all ${
                      engagementType === t.value
                        ? 'border-accent text-accent bg-accent-soft'
                        : 'border-border text-fg-muted hover:border-border-strong'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </Field>

            <Field label="Metodologia">
              <div className="grid grid-cols-3 gap-2">
                {METHODOLOGIES.map((m) => (
                  <button
                    type="button"
                    key={m.value}
                    onClick={() => setMethodology(m.value)}
                    className={`p-3 text-left rounded border transition-all ${
                      methodology === m.value
                        ? 'border-accent bg-accent-soft'
                        : 'border-border hover:border-border-strong'
                    }`}
                  >
                    <div
                      className={`text-sm font-medium ${
                        methodology === m.value ? 'text-accent' : 'text-fg'
                      }`}
                    >
                      {m.label}
                    </div>
                    <div className="text-2xs text-fg-muted mt-0.5">{m.hint}</div>
                  </button>
                ))}
              </div>
            </Field>

            <Field label="Data de início" required>
              <Input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="font-mono"
              />
            </Field>
          </div>
        </Card>

        <Card>
          <div className="p-5 space-y-4">
            <h2 className="text-xs font-medium uppercase tracking-wider text-accent">Escopo</h2>
            <Field
              label="Alvos"
              hint="um por linha — domínios, IPs, CIDRs, faixas"
              required
            >
              <Textarea
                required
                rows={6}
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                placeholder={'acme.com\nstock.acme.com\n10.0.0.0/24\napi.acme.com'}
                className="font-mono text-sm"
              />
            </Field>
            <Field label="Notas iniciais (opcional)">
              <Textarea
                rows={3}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="ROE, restrições, janela de testes, contatos..."
              />
            </Field>
          </div>
        </Card>

        <div className="flex justify-end gap-2 pt-2">
          <Link href="/projects">
            <Button variant="ghost" size="md" type="button">
              Cancelar
            </Button>
          </Link>
          <Button variant="primary" size="md" type="submit">
            Criar projeto
          </Button>
        </div>
      </form>
    </OperatorShell>
  );
}
