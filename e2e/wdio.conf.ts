/**
 * WebdriverIO configuration for Tauri E2E tests.
 *
 * Prerequisites:
 *   1. Build the app with automation enabled:
 *        TAURI_WEBVIEW_AUTOMATION=true npm run tauri build -- --profile dev
 *      or add a [profile.dev] section in Cargo.toml and use:
 *        cargo tauri build --profile dev
 *   2. Install tauri-driver:
 *        cargo install tauri-driver
 *   3. On Linux, xvfb-run is required for headless execution:
 *        xvfb-run npm run test:e2e
 */
import { spawn, type ChildProcess } from "child_process";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Resolved path to the built application binary.
const APPLICATION_PATH = path.resolve(
  __dirname,
  "../src-tauri/target/debug/anya-gui"
);

let tauriDriver: ChildProcess;

export const config: WebdriverIO.Config = {
  // ── Runner ──────────────────────────────────────────────────────────────────
  runner: "local",
  specs: ["./**/*.test.ts"],
  maxInstances: 1,
  bail: 0,

  // ── Capabilities ────────────────────────────────────────────────────────────
  capabilities: [
    {
      // WebdriverIO passes these to tauri-driver, which manages the WebKit/WebView session.
      "tauri:options": {
        application: APPLICATION_PATH,
      },
      browserName: "",
    } as WebdriverIO.Capabilities,
  ],

  // ── Framework ───────────────────────────────────────────────────────────────
  framework: "mocha",
  mochaOpts: {
    timeout: 30_000,
  },

  // ── Reporters ───────────────────────────────────────────────────────────────
  reporters: ["spec"],

  // ── Tauri driver lifecycle ─────────────────────────────────────────────────
  // onPrepare runs once before all workers — start tauri-driver here so only
  // one instance binds to port 4444.
  onPrepare: () => {
    tauriDriver = spawn("tauri-driver", [], {
      stdio: [null, process.stdout, process.stderr],
    });

    // Give tauri-driver time to bind to port 4444 before workers connect
    return new Promise<void>((resolve) => setTimeout(resolve, 2000));
  },

  onComplete: () => {
    tauriDriver?.kill();
  },

  // ── Connection ──────────────────────────────────────────────────────────────
  hostname: "localhost",
  port: 4444,
  path: "/",

  // ── TypeScript support ──────────────────────────────────────────────────────
  // Use tsx for ESM-compatible TypeScript compilation (ts-node has ESM issues
  // with "type": "module" in package.json).
  autoCompileOpts: {
    autoCompile: true,
    tsNodeOpts: {
      transpileOnly: true,
      project: path.resolve(__dirname, "../tsconfig.json"),
      esm: true,
    },
  },
};
