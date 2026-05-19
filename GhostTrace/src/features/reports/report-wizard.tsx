'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Sparkles, Check, Cpu, Cloud, Layers, Loader2, FileDown } from 'lucide-react';
import { Modal } from '@/components/ui/modal';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useStore } from '@/lib/mock/store';
import { generateReportViaApi } from '@/lib/ai';
import type { AIProviderId, EnhanceableField, Project } from '@/lib/types';

interface Props {
  open: boolean;
  onClose: () => void;
  project: Project;
  onComplete?: () => void;
  onExport?: () => void;
}

type Step = 'provider' | 'options' | 'generating' | 'done';

const FIELDS: { value: EnhanceableField; label: string }[] = [
  { value: 'description', label: 'Descrições' },
  { value: 'attackScenario', label: 'Cenários de ataque' },
  { value: 'recommendation', label: 'Recomendações' },
  { value: 'remediationNotes', label: 'Notas de remediação' }
];

const ICONS: Record<AIProviderId, typeof Sparkles> = {
  anthropic: Sparkles,
  gemini: Cloud,
  openrouter: Layers
};

export function ReportWizard({ open, onClose, project, onComplete, onExport }: Props) {
  const providers = useStore((s) => s.aiProviders);
  const vulnerabilities = useStore((s) =>
    s.vulnerabilities.filter((v) => v.projectId === project.id)
  );
  const bulkUpsert = useStore((s) => s.bulkUpsertVulnerabilities);
  const setConclusion = useStore((s) => s.setReportConclusion);

  const [step, setStep] = useState<Step>('provider');
  const [picked, setPicked] = useState<AIProviderId | 'none' | null>(null);
  const [fields, setFields] = useState<EnhanceableField[]>(['description', 'recommendation']);
  const [generateExecSummary, setGenerateExecSummary] = useState(true);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [enhancedCount, setEnhancedCount] = useState(0);

  function toggleField(f: EnhanceableField) {
    setFields((prev) => (prev.includes(f) ? prev.filter((x) => x !== f) : [...prev, f]));
  }

  async function start() {
    setStep('generating');
    setProgress(5);
    setError(null);
    try {
      const provider =
        picked && picked !== 'none' ? providers.find((p) => p.id === picked) : undefined;

      setProgress(20);
      const result = await generateReportViaApi({
        projectId: project.id,
        providerId: picked ?? 'none',
        apiKey: provider?.apiKey,
        model: provider?.model,
        fields: picked === 'none' ? [] : fields,
        executiveSummary: generateExecSummary && picked !== 'none',
        project,
        vulnerabilities
      });

      setProgress(80);
      if (result.vulnerabilities.length) {
        bulkUpsert(result.vulnerabilities);
      }
      if (result.conclusion) {
        setConclusion(project.id, result.conclusion);
      } else if (result.executiveSummary) {
        setConclusion(project.id, {
          priorityActions: [result.executiveSummary],
          midTermActions: ['Executar reteste após remediação.']
        });
      }
      setEnhancedCount(result.enhanced);
      setProgress(100);
      setStep('done');
      onComplete?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Falha ao gerar');
      setStep('options');
    }
  }

  function reset() {
    setStep('provider');
    setPicked(null);
    setProgress(0);
    setError(null);
    onClose();
  }

  return (
    <Modal
      open={open}
      onClose={reset}
      title="Gerar relatório enterprise"
      description="O operador escolhe o provedor de IA; GhostTrace mantém a evidência intacta."
      size="lg"
    >
      <div className="p-5">
        <div className="flex items-center gap-2 mb-5">
          <StepDot active={step === 'provider'} done={step !== 'provider'}>
            1
          </StepDot>
          <Line />
          <StepDot active={step === 'options'} done={step === 'generating' || step === 'done'}>
            2
          </StepDot>
          <Line />
          <StepDot active={step === 'generating'} done={step === 'done'}>
            3
          </StepDot>
          <Line />
          <StepDot active={step === 'done'}>✓</StepDot>
        </div>

        {error && (
          <p className="text-xs text-[var(--sev-critical)] mb-3 border border-[var(--sev-critical)]/30 rounded p-2">
            {error}
          </p>
        )}

        <AnimatePresence mode="wait">
          {step === 'provider' && (
            <motion.div
              key="provider"
              initial={{ opacity: 0, x: 10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.15 }}
            >
              <p className="text-sm text-fg-muted mb-4">
                Escolha o provedor que irá expandir e padronizar os campos. Comandos e payloads{' '}
                <strong className="text-fg">nunca</strong> são alterados.
              </p>
              <div className="grid gap-2">
                {providers.map((p) => {
                  const Icon = ICONS[p.id];
                  const selected = picked === p.id;
                  return (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => setPicked(p.id)}
                      className={`text-left p-4 rounded-md border transition-all ${
                        selected
                          ? 'border-accent bg-accent-soft'
                          : 'border-border hover:border-border-strong bg-surface-2'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div
                          className={`w-9 h-9 rounded flex items-center justify-center shrink-0 ${
                            selected ? 'bg-accent text-bg' : 'bg-surface-3 text-fg-muted'
                          }`}
                        >
                          <Icon size={16} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-fg">{p.label}</span>
                            {p.enabled && p.apiKey ? (
                              <Badge mono tone="accent">
                                CONFIGURADO
                              </Badge>
                            ) : (
                              <Badge mono>SEM API KEY</Badge>
                            )}
                          </div>
                          <p className="text-2xs text-fg-dim font-mono mt-1">model: {p.model}</p>
                        </div>
                        {selected && <Check size={16} className="text-accent shrink-0 mt-2" />}
                      </div>
                    </button>
                  );
                })}
                <button
                  type="button"
                  onClick={() => setPicked('none')}
                  className={`text-left p-4 rounded-md border transition-all ${
                    picked === 'none'
                      ? 'border-accent bg-accent-soft'
                      : 'border-border hover:border-border-strong bg-surface-2'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded flex items-center justify-center bg-surface-3 text-fg-muted">
                      <Cpu size={16} />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-fg">Sem IA</div>
                      <p className="text-xs text-fg-muted mt-0.5">Apenas estruturação dos dados atuais.</p>
                    </div>
                  </div>
                </button>
              </div>
              <div className="flex justify-end gap-2 mt-5">
                <Button variant="ghost" onClick={reset}>
                  Cancelar
                </Button>
                <Button variant="primary" disabled={!picked} onClick={() => setStep('options')}>
                  Continuar
                </Button>
              </div>
            </motion.div>
          )}

          {step === 'options' && (
            <motion.div
              key="options"
              initial={{ opacity: 0, x: 10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.15 }}
            >
              <div className="space-y-2">
                {FIELDS.map((f) => (
                  <label
                    key={f.value}
                    className="flex items-center gap-3 p-3 border border-border rounded-md hover:border-border-strong cursor-pointer bg-surface-2"
                  >
                    <input
                      type="checkbox"
                      checked={fields.includes(f.value)}
                      onChange={() => toggleField(f.value)}
                      className="accent-accent"
                      disabled={picked === 'none'}
                    />
                    <span className="text-sm text-fg">{f.label}</span>
                  </label>
                ))}
                <label className="flex items-center gap-3 p-3 border border-border rounded-md bg-surface-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={generateExecSummary}
                    onChange={() => setGenerateExecSummary((v) => !v)}
                    className="accent-accent"
                    disabled={picked === 'none'}
                  />
                  <span className="text-sm text-fg">Gerar conclusão executiva</span>
                </label>
              </div>
              <div className="flex justify-between gap-2 mt-5">
                <Button variant="ghost" onClick={() => setStep('provider')}>
                  ← Voltar
                </Button>
                <Button variant="primary" onClick={start}>
                  <Sparkles size={14} /> Gerar relatório
                </Button>
              </div>
            </motion.div>
          )}

          {step === 'generating' && (
            <motion.div key="generating" className="py-12 flex flex-col items-center">
              <Loader2 size={32} className="text-accent animate-spin" />
              <p className="mt-4 text-sm text-fg">Compondo relatório...</p>
              <div className="w-full max-w-sm mt-6 h-1 bg-surface-2 rounded overflow-hidden">
                <div className="h-full bg-accent transition-all" style={{ width: `${progress}%` }} />
              </div>
            </motion.div>
          )}

          {step === 'done' && (
            <motion.div key="done" className="py-8 text-center">
              <div className="w-12 h-12 mx-auto rounded-full bg-accent-soft flex items-center justify-center text-accent border border-accent/40">
                <Check size={20} />
              </div>
              <p className="mt-4 text-sm font-medium text-fg">Relatório atualizado.</p>
              <p className="text-xs text-fg-muted mt-1">
                {enhancedCount > 0
                  ? `${enhancedCount} campos refinados pela IA.`
                  : 'Dados estruturados sem alteração de texto.'}
              </p>
              <div className="flex justify-center gap-2 mt-5">
                <Button variant="ghost" onClick={reset}>
                  Fechar
                </Button>
                <Button
                  variant="primary"
                  onClick={() => {
                    onExport?.();
                    reset();
                  }}
                >
                  <FileDown size={14} /> Exportar JSON
                </Button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Modal>
  );
}

function StepDot({
  children,
  active,
  done
}: {
  children: React.ReactNode;
  active?: boolean;
  done?: boolean;
}) {
  return (
    <div
      className={`w-6 h-6 rounded-full flex items-center justify-center text-2xs font-mono font-medium border ${
        done
          ? 'bg-accent text-bg border-accent'
          : active
            ? 'bg-accent-soft text-accent border-accent'
            : 'bg-surface-2 text-fg-dim border-border'
      }`}
    >
      {children}
    </div>
  );
}

function Line() {
  return <div className="flex-1 h-px bg-border" />;
}
