// Mock for @tauri-apps/api/core — replaces the real IPC bridge in unit tests.
import { vi } from "vitest";

export const invoke = vi.fn().mockResolvedValue({
  text: "For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.",
  reference: "John 3:16",
});
