'use client';

import { Suspense } from 'react';
import { HistoryWorkspace } from '@/features/history/HistoryWorkspace';

function Loading() {
  return (
    <p className="h-full flex items-center justify-center text-zinc-500 font-mono text-sm">
      A carregar HTTP History…
    </p>
  );
}

export default function HistoryPage() {
  return (
    <Suspense fallback={<Loading />}>
      <HistoryWorkspace />
    </Suspense>
  );
}
