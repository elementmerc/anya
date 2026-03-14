import { useState, useEffect, useCallback } from "react";
import { loadSettings, saveSettingsToDb } from "@/lib/db";

export type Theme = "dark" | "light";

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>("dark");

  // Load persisted theme on mount
  useEffect(() => {
    loadSettings()
      .then((s) => {
        if (s.theme) apply(s.theme);
      })
      .catch(() => {
        /* ignore DB errors on first launch */
      });
  }, []);

  function apply(t: Theme) {
    setThemeState(t);
    if (t === "light") {
      document.documentElement.setAttribute("data-theme", "light");
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  }

  const toggleTheme = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    apply(next);
    saveSettingsToDb({ theme: next }).catch(() => {});
  }, [theme]);

  const setTheme = useCallback(
    (t: Theme) => {
      apply(t);
      saveSettingsToDb({ theme: t }).catch(() => {});
    },
    []
  );

  return { theme, toggleTheme, setTheme };
}
