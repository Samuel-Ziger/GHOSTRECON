'use client';

import { useState } from 'react';
import { Modal } from '@/components/ui/modal';
import { Button } from '@/components/ui/button';
import { Input, Textarea, Field } from '@/components/ui/input';
import { useStore } from '@/lib/mock/store';
import type { TimelineEventType } from '@/lib/types';
import { EVENT_LABEL } from '@/lib/utils/severity';

const TYPES: TimelineEventType[] = [
  'recon',
  'enumeration',
  'creds',
  'rce',
  'shell',
  'privesc',
  'pivot',
  'lateral',
  'exfil',
  'persistence',
  'note'
];

interface Props {
  open: boolean;
  onClose: () => void;
  projectId: string;
}

export function EventComposer({ open, onClose, projectId }: Props) {
  const addEvent = useStore((s) => s.addTimelineEvent);
  const [type, setType] = useState<TimelineEventType>('note');
  const [title, setTitle] = useState('');
  const [host, setHost] = useState('');
  const [details, setDetails] = useState('');
  const [ts, setTs] = useState(() => new Date().toISOString().slice(0, 16));
  const [saving, setSaving] = useState(false);

  function reset() {
    setType('note');
    setTitle('');
    setHost('');
    setDetails('');
    setTs(new Date().toISOString().slice(0, 16));
  }

  function handleClose() {
    reset();
    onClose();
  }

  async function submit() {
    if (!title.trim()) return;
    setSaving(true);
    try {
      addEvent({
        projectId,
        type,
        title: title.trim(),
        host: host.trim() || undefined,
        details: details.trim() || undefined,
        ts: new Date(ts).toISOString()
      });
      handleClose();
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Registrar evento"
      description="Timeline ofensiva — recon, exploit, pivot, creds..."
    >
      <div className="p-5 space-y-4">
        <Field label="Tipo">
          <select
            value={type}
            onChange={(e) => setType(e.target.value as TimelineEventType)}
            className="w-full h-9 px-3 rounded-md border border-border bg-surface-2 text-sm text-fg"
          >
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {EVENT_LABEL[t]}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Título">
          <Input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Ex.: Reverse shell www-data no Edge"
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Host">
            <Input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="3.212.54.4"
              className="font-mono text-xs"
            />
          </Field>
          <Field label="Timestamp">
            <Input
              type="datetime-local"
              value={ts}
              onChange={(e) => setTs(e.target.value)}
              className="font-mono text-xs"
            />
          </Field>
        </div>
        <Field label="Detalhes">
          <Textarea
            value={details}
            onChange={(e) => setDetails(e.target.value)}
            rows={4}
            placeholder="Comandos, artefatos, contexto..."
          />
        </Field>
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" onClick={handleClose}>
            Cancelar
          </Button>
          <Button variant="primary" onClick={submit} disabled={saving || !title.trim()}>
            {saving ? 'Salvando...' : 'Registrar'}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
