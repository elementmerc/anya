import { useEffect } from "react";

interface ShortcutActions {
  openFile: () => void;
  batchAnalysis: () => void;
  switchTab: (index: number) => void;
  toggleTeacher: () => void;
  exportJson: () => void;
  closeModal: () => void;
  showShortcuts: () => void;
}

export function useKeyboardShortcuts(actions: ShortcutActions, enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;

    const handler = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      const inInput = ["INPUT", "TEXTAREA"].includes((e.target as HTMLElement).tagName);

      if (mod && e.key === "o") { e.preventDefault(); actions.openFile(); }
      else if (mod && e.key === "b") { e.preventDefault(); actions.batchAnalysis(); }
      else if (mod && e.key === "e") { e.preventDefault(); actions.exportJson(); }
      else if (e.key === "Escape") { actions.closeModal(); }
      else if (e.key === "?" && !inInput) { e.preventDefault(); actions.showShortcuts(); }
      else if (!inInput && !mod && e.key >= "1" && e.key <= "9") {
        e.preventDefault();
        actions.switchTab(parseInt(e.key) - 1);
      }
      else if (!inInput && !mod && e.key.toLowerCase() === "t") {
        e.preventDefault();
        actions.toggleTeacher();
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [actions, enabled]);
}
