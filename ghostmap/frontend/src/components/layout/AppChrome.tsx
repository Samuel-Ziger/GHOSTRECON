'use client';

import { usePathname } from 'next/navigation';
import { Sidebar } from '@/components/layout/Sidebar';
import { TopBar } from '@/components/layout/TopBar';

const IMMERSIVE_PREFIXES = ['/history', '/ghostrecon'];

export function AppChrome({ children }: { children: React.ReactNode }) {
  const path = usePathname() || '';
  const immersive = IMMERSIVE_PREFIXES.some(
    (p) => path === p || path.startsWith(`${p}/`)
  );

  if (immersive) {
    return (
      <div className="h-screen min-h-0 flex flex-col overflow-hidden">{children}</div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0">
        <TopBar />
        <main className="flex-1 min-w-0 min-h-0">{children}</main>
      </div>
    </div>
  );
}
