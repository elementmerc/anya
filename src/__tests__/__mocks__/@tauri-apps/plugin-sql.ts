// Mock for @tauri-apps/plugin-sql
import { vi } from "vitest";

const db = {
  execute: vi.fn().mockResolvedValue(undefined),
  select: vi.fn().mockResolvedValue([]),
};

export default {
  load: vi.fn().mockResolvedValue(db),
};
