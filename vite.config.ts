import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(() => ({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./ui"),
    },
  },
  // Vite options tailored for Tauri development
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      // Ignore the Rust source and target directories
      ignored: ["**/src/**", "**/src-tauri/**", "**/target/**"],
    },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  build: {
    // Tauri uses Chromium on Linux and WebKit on macOS and Windows
    target:
      process.env.TAURI_ENV_PLATFORM === "windows"
        ? "chrome105"
        : process.env.TAURI_ENV_PLATFORM === "macos"
          ? "safari13"
          : "chrome105",
    minify: (process.env.TAURI_ENV_DEBUG ? false : "esbuild") as "esbuild" | false,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
    outDir: "dist",
    rollupOptions: {
      input: "./index.html",
    },
  },
}));
