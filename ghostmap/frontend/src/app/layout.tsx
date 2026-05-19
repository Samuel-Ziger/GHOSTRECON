import "@/styles/globals.css";
import "reactflow/dist/style.css";
import type { Metadata } from "next";
import { AppChrome } from "@/components/layout/AppChrome";
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
        <AppChrome>{children}</AppChrome>
      </body>
    </html>
  );
}
