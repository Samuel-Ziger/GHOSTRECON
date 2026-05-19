import type { Config } from "tailwindcss";

// Paleta cyberpunk minimalista — fundo profundo, accent neon controlado.
export default {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg:       "#070811",
        panel:    "#0c0f1a",
        border:   "#1a1e2e",
        ink:      "#e6e8ef",
        mute:     "#7c8194",
        accent:   "#7c5cff",   // purple primario
        accent2:  "#22d3ee",   // cyan
        warn:     "#f59e0b",
        danger:   "#ef4444",
        ok:       "#10b981",
        heat: {
          low:    "#1e293b",
          mid:    "#a16207",
          high:   "#dc2626",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "monospace"],
      },
      boxShadow: {
        node: "0 0 0 1px #1a1e2e, 0 0 24px rgba(124,92,255,.15)",
        glow: "0 0 40px rgba(124,92,255,.25)",
      },
      animation: {
        pulseSoft: "pulseSoft 2.2s ease-in-out infinite",
      },
      keyframes: {
        pulseSoft: {
          "0%,100%": { opacity: "0.85" },
          "50%": { opacity: "1" },
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
