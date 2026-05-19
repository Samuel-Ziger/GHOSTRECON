'use client';

import { useMemo, useState } from 'react';
import { Plus, Pencil, Trash2, Link2 } from 'lucide-react';
import { Modal } from '@/components/ui/modal';
import { Button } from '@/components/ui/button';
import { Input, Textarea, Field } from '@/components/ui/input';
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { ChainGraph } from './chain-graph';
import { orderAttackChain } from '@/lib/api/order-chain';
import { useStore } from '@/lib/mock/store';
import type { AttackChainNode, ChainPrivilege, ChainStep } from '@/lib/types';
import { PRIVILEGE_LABEL } from '@/lib/utils/severity';

const PRIVILEGES: ChainPrivilege[] = ['unauth', 'user', 'root'];

interface Props {
  projectId: string;
  nodes: AttackChainNode[];
}

export function ChainEditor({ projectId, nodes }: Props) {
  const upsertNode = useStore((s) => s.upsertAttackChainNode);
  const deleteNode = useStore((s) => s.deleteAttackChainNode);
  const linkNodes = useStore((s) => s.linkChainNodes);

  const ordered = useMemo(() => orderAttackChain(nodes), [nodes]);
  const [editing, setEditing] = useState<AttackChainNode | null>(null);
  const [composerOpen, setComposerOpen] = useState(false);

  function openNew() {
    setEditing({
      id: '',
      projectId,
      host: '',
      ip: '',
      privilege: 'user',
      steps: [{ order: 1, action: '' }],
      nextNodeIds: []
    });
    setComposerOpen(true);
  }

  function openEdit(node: AttackChainNode) {
    setEditing({ ...node, steps: [...node.steps] });
    setComposerOpen(true);
  }

  function saveNode() {
    if (!editing || !editing.host.trim()) return;
    const steps = editing.steps
      .filter((s) => s.action.trim())
      .map((s, i) => ({ ...s, order: i + 1 }));
    const saved = upsertNode({
      ...editing,
      host: editing.host.trim(),
      ip: editing.ip?.trim() || undefined,
      steps: steps.length ? steps : [{ order: 1, action: 'Acesso estabelecido' }]
    });
    if (!editing.id && ordered.length > 0) {
      const tail = ordered[ordered.length - 1];
      linkNodes(tail.id, saved.id);
    }
    setComposerOpen(false);
    setEditing(null);
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Visualização</CardTitle>
          <Button variant="primary" size="sm" onClick={openNew}>
            <Plus size={12} /> Adicionar nó
          </Button>
        </CardHeader>
        <CardBody>
          {ordered.length === 0 ? (
            <p className="text-sm text-fg-muted text-center py-8">
              Nenhum host na cadeia. Adicione o primeiro nó (ex.: INTERNET → EDGE).
            </p>
          ) : (
            <ChainGraph nodes={ordered} />
          )}
        </CardBody>
      </Card>

      {ordered.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Editar nós</CardTitle>
          </CardHeader>
          <CardBody className="p-0 divide-y divide-border">
            {ordered.map((node, idx) => (
              <div
                key={node.id}
                className="flex items-center justify-between px-4 py-3 hover:bg-surface-2/60"
              >
                <div className="min-w-0">
                  <span className="text-2xs font-mono text-fg-dim mr-2">
                    {String(idx + 1).padStart(2, '0')}
                  </span>
                  <span className="text-sm text-fg font-medium">{node.host}</span>
                  {node.ip && (
                    <span className="text-2xs font-mono text-fg-muted ml-2">{node.ip}</span>
                  )}
                  <span className="text-2xs text-fg-dim ml-2">
                    · {PRIVILEGE_LABEL[node.privilege]} · {node.steps.length} passos
                  </span>
                  {node.nextNodeIds.length > 0 && (
                    <span className="text-2xs text-accent ml-2 inline-flex items-center gap-1">
                      <Link2 size={10} /> → {node.nextNodeIds.length}
                    </span>
                  )}
                </div>
                <div className="flex gap-1 shrink-0">
                  <Button variant="ghost" size="sm" onClick={() => openEdit(node)}>
                    <Pencil size={12} />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-[var(--sev-critical)] hover:text-[var(--sev-critical)]"
                    onClick={() => {
                      if (confirm(`Remover nó "${node.host}"?`)) deleteNode(node.id);
                    }}
                  >
                    <Trash2 size={12} />
                  </Button>
                </div>
              </div>
            ))}
          </CardBody>
        </Card>
      )}

      {editing && (
        <Modal
          open={composerOpen}
          onClose={() => {
            setComposerOpen(false);
            setEditing(null);
          }}
          title={editing.id ? 'Editar nó' : 'Novo nó'}
          size="lg"
        >
          <div className="p-5 space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <Field label="Host / rótulo">
                <Input
                  value={editing.host}
                  onChange={(e) => setEditing({ ...editing, host: e.target.value })}
                  placeholder="EDGE, BACKDROP CMS..."
                />
              </Field>
              <Field label="IP">
                <Input
                  value={editing.ip ?? ''}
                  onChange={(e) => setEditing({ ...editing, ip: e.target.value })}
                  placeholder="10.0.0.1"
                  className="font-mono text-xs"
                />
              </Field>
            </div>
            <Field label="Privilégio">
              <select
                value={editing.privilege}
                onChange={(e) =>
                  setEditing({ ...editing, privilege: e.target.value as ChainPrivilege })
                }
                className="w-full h-9 px-3 rounded-md border border-border bg-surface-2 text-sm"
              >
                {PRIVILEGES.map((p) => (
                  <option key={p} value={p}>
                    {PRIVILEGE_LABEL[p]}
                  </option>
                ))}
              </select>
            </Field>

            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-fg-muted uppercase tracking-wider">
                  Passos neste host
                </span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() =>
                    setEditing({
                      ...editing,
                      steps: [
                        ...editing.steps,
                        { order: editing.steps.length + 1, action: '' }
                      ]
                    })
                  }
                >
                  <Plus size={12} /> Passo
                </Button>
              </div>
              <div className="space-y-2">
                {editing.steps.map((step, i) => (
                  <StepRow
                    key={i}
                    step={step}
                    onChange={(action) => {
                      const steps = [...editing.steps];
                      steps[i] = { ...steps[i], action };
                      setEditing({ ...editing, steps });
                    }}
                    onRemove={() => {
                      const steps = editing.steps.filter((_, j) => j !== i);
                      setEditing({ ...editing, steps });
                    }}
                  />
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="ghost" onClick={() => setComposerOpen(false)}>
                Cancelar
              </Button>
              <Button variant="primary" onClick={saveNode} disabled={!editing.host.trim()}>
                Salvar nó
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

function StepRow({
  step,
  onChange,
  onRemove
}: {
  step: ChainStep;
  onChange: (action: string) => void;
  onRemove: () => void;
}) {
  return (
    <div className="flex gap-2 items-start">
      <span className="text-2xs font-mono text-fg-dim w-6 pt-2">{step.order}</span>
      <Textarea
        value={step.action}
        onChange={(e) => onChange(e.target.value)}
        rows={2}
        placeholder="Ação realizada neste host..."
        className="flex-1 text-sm"
      />
      <Button type="button" variant="ghost" size="sm" onClick={onRemove}>
        <Trash2 size={12} />
      </Button>
    </div>
  );
}
