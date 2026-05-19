import "@/styles/globals.css";
import "reactflow/dist/style.css";
import type { Metadata } from "next";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";
import { WSBridge } from "@/components/layout/WSBridge";

export const metadata: Metadata = {
  title: "GhostMap",
  description: "Visual application mapping for offensive security",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR">
      <body className="bg-bg text-ink">
        <WSBridge />
        <div className="flex min-h-screen">
          <Sidebar />
          <div className="flex flex-col flex-1 min-w-0">
            <TopBar />
            <main className="flex-1 min-w-0 min-h-0">{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
