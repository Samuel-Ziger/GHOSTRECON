import type { Metadata } from 'next';
import { GeistSans } from 'geist/font/sans';
import { GeistMono } from 'geist/font/mono';
import { StoreProvider } from '@/components/providers/store-provider';
import './globals.css';

export const metadata: Metadata = {
  title: 'GHOSTRECON · GhostTrace — Anotações ofensivas',
  description:
    'Área de anotação do GHOSTRECON — documentação viva de Pentest, Red Team e Bug Bounty (GhostTrace).',
  icons: { icon: '/favicon.svg' }
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body className="font-sans antialiased min-h-screen">
        <StoreProvider>{children}</StoreProvider>
      </body>
    </html>
  );
}
