'use client';

import { useRef, type RefObject } from 'react';
import { Image as ImageIcon, Trash2 } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/empty';
import { useStore } from '@/lib/mock/store';
import type { Evidence } from '@/lib/types';

interface Props {
  projectId: string;
  items: Evidence[];
  /** Ref compartilhado com o botão da topbar para upload */
  uploadRef?: RefObject<HTMLInputElement>;
}

export function EvidenceGrid({ projectId, items, uploadRef }: Props) {
  const addEvidence = useStore((s) => s.addEvidence);
  const deleteEvidence = useStore((s) => s.deleteEvidence);
  const localRef = useRef<HTMLInputElement>(null);
  const inputRef = uploadRef ?? localRef;

  function onFiles(files: FileList | null) {
    if (!files?.length) return;
    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = () => {
        const dataUrl = typeof reader.result === 'string' ? reader.result : undefined;
        addEvidence({
          projectId,
          filename: file.name,
          mime: file.type || 'application/octet-stream',
          size: file.size,
          vulnerabilityIds: [],
          thumbnailUrl: file.type.startsWith('image/') ? dataUrl : undefined,
          caption: file.name
        });
      };
      reader.readAsDataURL(file);
    });
  }

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        multiple
        accept="image/*,.pcap,.txt,.json,.zip"
        className="hidden"
        onChange={(e) => {
          onFiles(e.target.files);
          e.target.value = '';
        }}
      />
      {items.length === 0 ? (
        <Empty
          icon={ImageIcon}
          title="Nenhuma evidência"
          description="Envie screenshots, PCAPs ou artefatos. Armazenados localmente neste navegador."
          action={
            <Button variant="primary" size="md" onClick={() => inputRef.current?.click()}>
              Enviar arquivo
            </Button>
          }
        />
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {items.map((ev) => (
            <Card key={ev.id} className="overflow-hidden group">
              <div className="aspect-video bg-surface-2 flex items-center justify-center relative">
                {ev.thumbnailUrl ? (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img
                    src={ev.thumbnailUrl}
                    alt={ev.filename}
                    className="w-full h-full object-cover"
                  />
                ) : (
                  <ImageIcon size={32} className="text-fg-dim" />
                )}
                <button
                  type="button"
                  onClick={() => deleteEvidence(ev.id)}
                  className="absolute top-2 right-2 p-1.5 rounded bg-bg/80 border border-border opacity-0 group-hover:opacity-100 transition-opacity text-fg-muted hover:text-[var(--sev-critical)]"
                  title="Remover"
                >
                  <Trash2 size={12} />
                </button>
              </div>
              <div className="p-3 border-t border-border">
                <p className="text-xs text-fg truncate font-mono">{ev.filename}</p>
                <p className="text-2xs text-fg-dim mt-0.5">
                  {(ev.size / 1024).toFixed(1)} KB · {ev.mime}
                </p>
              </div>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
