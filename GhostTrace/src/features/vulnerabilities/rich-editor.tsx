'use client';

import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import Placeholder from '@tiptap/extension-placeholder';
import { Bold, Italic, List, ListOrdered, Code, Quote } from 'lucide-react';
import { cn } from '@/lib/utils/cn';

interface Props {
  value: string;
  onChange: (markdown: string) => void;
  placeholder?: string;
  minHeight?: number;
}

export function RichEditor({ value, onChange, placeholder, minHeight = 140 }: Props) {
  const editor = useEditor({
    extensions: [
      StarterKit.configure({ codeBlock: { HTMLAttributes: { class: 'tt-codeblock' } } }),
      Placeholder.configure({ placeholder: placeholder || 'Escreva aqui...' })
    ],
    content: value,
    onUpdate({ editor }) {
      onChange(editor.getHTML());
    },
    editorProps: {
      attributes: {
        class: 'tiptap text-sm text-fg'
      }
    },
    immediatelyRender: false
  });

  if (!editor) return null;

  return (
    <div className="border border-border rounded-md bg-surface-2 focus-within:border-accent/60 focus-within:shadow-glow-soft transition-all">
      <div className="flex items-center gap-0.5 px-2 py-1.5 border-b border-border">
        <TBtn active={editor.isActive('bold')} onClick={() => editor.chain().focus().toggleBold().run()}>
          <Bold size={13} />
        </TBtn>
        <TBtn active={editor.isActive('italic')} onClick={() => editor.chain().focus().toggleItalic().run()}>
          <Italic size={13} />
        </TBtn>
        <span className="w-px h-4 bg-border mx-0.5" />
        <TBtn active={editor.isActive('bulletList')} onClick={() => editor.chain().focus().toggleBulletList().run()}>
          <List size={13} />
        </TBtn>
        <TBtn active={editor.isActive('orderedList')} onClick={() => editor.chain().focus().toggleOrderedList().run()}>
          <ListOrdered size={13} />
        </TBtn>
        <span className="w-px h-4 bg-border mx-0.5" />
        <TBtn active={editor.isActive('codeBlock')} onClick={() => editor.chain().focus().toggleCodeBlock().run()}>
          <Code size={13} />
        </TBtn>
        <TBtn active={editor.isActive('blockquote')} onClick={() => editor.chain().focus().toggleBlockquote().run()}>
          <Quote size={13} />
        </TBtn>
      </div>
      <div className="px-3 py-2" style={{ minHeight }}>
        <EditorContent editor={editor} />
      </div>
    </div>
  );
}

function TBtn({
  active,
  onClick,
  children
}: {
  active?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'h-6 w-6 rounded flex items-center justify-center transition-colors',
        active ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:text-fg hover:bg-surface-3'
      )}
    >
      {children}
    </button>
  );
}
