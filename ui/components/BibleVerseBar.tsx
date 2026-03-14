import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Verse {
  text: string;
  reference: string;
}

const CYCLE_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

export function BibleVerseBar() {
  const [verse, setVerse] = useState<Verse | null>(null);

  const fetchVerse = useCallback(async () => {
    try {
      const v = await invoke<Verse>("get_random_verse");
      setVerse(v);
    } catch {
      // silently ignore — verse bar is non-critical
    }
  }, []);

  useEffect(() => {
    fetchVerse();
    const id = setInterval(fetchVerse, CYCLE_INTERVAL_MS);
    return () => clearInterval(id);
  }, [fetchVerse]);

  if (!verse) return null;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 16px",
        height: "36px",
        flexShrink: 0,
        background: "var(--bg-elevated)",
        borderTop: "1px solid var(--border)",
        overflow: "hidden",
        gap: "12px",
      }}
    >
      <span
        className="selectable"
        style={{
          fontSize: "12px",
          color: "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          flex: 1,
          fontStyle: "italic",
        }}
      >
        {verse.text}
      </span>
      <span
        className="selectable"
        style={{
          fontSize: "12px",
          color: "var(--text-primary)",
          whiteSpace: "nowrap",
        }}
      >
        {verse.reference}
      </span>
    </div>
  );
}
