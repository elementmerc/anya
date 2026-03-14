import { useState, useEffect, useCallback } from "react";
import { loadSettings, saveSettingsToDb } from "@/lib/db";

export type FontSize = "small" | "default" | "large" | "xl";

const FONT_SIZE_PX: Record<FontSize, string> = {
  small:   "13px",
  default: "14px",
  large:   "15px",
  xl:      "16px",
};

const LS_KEY = "anya-font-size";

export function applyFontSize(size: FontSize) {
  const px = FONT_SIZE_PX[size];
  document.documentElement.style.setProperty("--font-size-base", px);
  localStorage.setItem(LS_KEY, px);
}

export function useFontSize() {
  const [fontSize, setFontSizeState] = useState<FontSize>("default");

  useEffect(() => {
    loadSettings()
      .then((s) => {
        if (s.font_size) {
          setFontSizeState(s.font_size);
          applyFontSize(s.font_size);
        }
      })
      .catch(() => {});
  }, []);

  const setFontSize = useCallback((size: FontSize) => {
    setFontSizeState(size);
    applyFontSize(size);
    saveSettingsToDb({ font_size: size }).catch(() => {});
  }, []);

  return { fontSize, setFontSize };
}
