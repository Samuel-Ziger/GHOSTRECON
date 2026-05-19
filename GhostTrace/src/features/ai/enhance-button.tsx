'use client';

import { useState } from 'react';
import { Sparkles, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useStore } from '@/lib/mock/store';
import { enhanceFieldViaApi } from '@/lib/ai';
import type { EnhanceableField, Vulnerability } from '@/lib/types';

interface Props {
  field: EnhanceableField;
  currentValue: string;
  vuln: Pick<Vulnerability, 'title' | 'severity' | 'cwe' | 'tags' | 'targets'>;
  onApply: (improved: string) => void;
}

export function EnhanceButton({ field, currentValue, vuln, onApply }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const active = useStore((s) => s.getActiveAIProvider());

  async function run() {
    setLoading(true);
    setError(null);
    try {
      if (!active?.apiKey?.trim()) {
        setError('Configure um provider em Configurações');
        return;
      }
      const result = await enhanceFieldViaApi({
        providerId: active.id,
        apiKey: active.apiKey,
        model: active.model,
        field,
        input: currentValue,
        vuln
      });
      onApply(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Falha na IA');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onClick={run}
        disabled={loading}
        className="text-accent hover:text-accent hover:bg-accent-soft"
        title={
          active?.apiKey
            ? `Aprimorar com ${active.label}`
            : 'Configure um provider em Configurações'
        }
      >
        {loading ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
        Aprimorar
      </Button>
      {error && <span className="text-2xs text-[var(--sev-critical)] max-w-[200px] text-right">{error}</span>}
    </div>
  );
}
