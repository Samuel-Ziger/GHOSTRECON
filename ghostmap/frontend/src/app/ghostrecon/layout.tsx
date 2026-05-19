import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'GHOSTRECON · GhostMap',
  description: 'Mapa MITRE/OWASP ao vivo e grafo de achados do recon'
};

/** Hub GHOSTRECON: ecrã inteiro (cobre sidebar do GhostMap standalone). */
export default function GhostreconLayout({ children }: { children: React.ReactNode }) {
  return <div className="fixed inset-0 z-[100] bg-bg text-ink overflow-hidden">{children}</div>;
}
