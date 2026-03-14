import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/__tests__/setup.ts"],
    include: ["src/__tests__/**/*.test.{ts,tsx}"],
    // Mock Tauri's IPC — the desktop bridge is not available in jsdom.
    alias: {
      "@tauri-apps/api/core": path.resolve(
        __dirname,
        "src/__tests__/__mocks__/@tauri-apps/api/core.ts"
      ),
      "@tauri-apps/plugin-sql": path.resolve(
        __dirname,
        "src/__tests__/__mocks__/@tauri-apps/plugin-sql.ts"
      ),
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "ui"),
    },
  },
});
