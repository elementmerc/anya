/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./ui/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Geist", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["Geist Mono", "ui-monospace", "monospace"],
      },
      colors: {
        // Design token colours (mirror CSS variables for Tailwind class usage)
        bg: {
          base: "var(--bg-base)",
          surface: "var(--bg-surface)",
          elevated: "var(--bg-elevated)",
        },
        border: "var(--border)",
        text: {
          primary: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          muted: "var(--text-muted)",
        },
        accent: "var(--accent)",
        risk: {
          low: "var(--risk-low)",
          medium: "var(--risk-medium)",
          high: "var(--risk-high)",
          critical: "var(--risk-critical)",
        },
        entropy: {
          safe: "var(--entropy-safe)",
          packed: "var(--entropy-packed)",
          encrypted: "var(--entropy-encrypted)",
        },
      },
      keyframes: {
        "count-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "row-in": {
          "0%": { opacity: "0", transform: "translateX(-4px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        "tooltip-in": {
          "0%": { opacity: "0", transform: "scale(0.97)" },
          "100%": { opacity: "1", transform: "scale(1)" },
        },
      },
      animation: {
        "count-up": "count-up 0.4s ease-out forwards",
        "fade-in": "fade-in 0.1s ease-out",
        "row-in": "row-in 0.15s ease-out forwards",
        "tooltip-in": "tooltip-in 0.08s ease-out",
      },
    },
  },
  plugins: [],
};
