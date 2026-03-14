import React, { Suspense, useState, lazy, useEffect, useCallback } from "react";
import { SplashScreen } from "@/components/SplashScreen";
import { useAnalysis } from "@/hooks/useAnalysis";
import { useTheme } from "@/hooks/useTheme";
import { useFontSize } from "@/hooks/useFontSize";
import { TeacherModeContext, type TeacherModeContextValue, type TeacherFocusItem } from "@/hooks/useTeacherMode";
import { loadTeacherSettings, saveTeacherSettings, loadSettings, saveSettingsToDb } from "@/lib/db";
import { BibleVerseBar } from "@/components/BibleVerseBar";
import DropZone from "@/components/DropZone";
import TopBar from "@/components/TopBar";
import TabNav from "@/components/TabNav";
import SettingsModal from "@/components/SettingsModal";
import TeacherSidebar from "@/components/TeacherSidebar";
import type { TabName, AnalysisResult } from "@/types/analysis";

// Lazy-load tab components (code splitting)
const OverviewTab  = lazy(() => import("@/components/tabs/OverviewTab"));
const EntropyTab   = lazy(() => import("@/components/tabs/EntropyTab"));
const ImportsTab   = lazy(() => import("@/components/tabs/ImportsTab"));
const SectionsTab  = lazy(() => import("@/components/tabs/SectionsTab"));
const StringsTab   = lazy(() => import("@/components/tabs/StringsTab"));
const SecurityTab  = lazy(() => import("@/components/tabs/SecurityTab"));
const MitreTab     = lazy(() => import("@/components/tabs/MitreTab"));

function TabFallback() {
  return (
    <div className="flex items-center justify-center h-32">
      <div
        className="w-5 h-5 border-2 rounded-full animate-spin"
        style={{ borderColor: "var(--border)", borderTopColor: "var(--accent)" }}
      />
    </div>
  );
}

function tabHasBadge(id: TabName, result: AnalysisResult | null): boolean {
  if (!result?.pe_analysis) return false;
  const pe = result.pe_analysis;
  switch (id) {
    case "imports":  return pe.imports.suspicious_api_count > 0 || pe.anti_analysis.length > 0;
    case "sections": return pe.sections.some((s) => s.is_wx);
    case "security": return !pe.security.aslr_enabled || !pe.security.dep_enabled;
    case "entropy":  return pe.sections.some((s) => s.entropy > 7.0);
    case "mitre":    return (result.mitre_techniques?.length ?? 0) > 0;
    default:         return false;
  }
}

export default function App() {
  const { result, riskScore, isLoading, error, analyse, reset } = useAnalysis();
  const { theme, toggleTheme } = useTheme();
  const { fontSize, setFontSize } = useFontSize();
  const [activeTab, setActiveTab] = useState<TabName>("overview");
  const [showSettings, setShowSettings] = useState(false);

  // ── Splash screen ─────────────────────────────────────────────────────────
  const [splashVisible, setSplashVisible] = useState(true);
  const [splashHiding, setSplashHiding] = useState(false);
  const [appReady, setAppReady] = useState(false);

  useEffect(() => {
    const signalReady = async () => {
      await document.fonts.ready;
      await new Promise(resolve => requestAnimationFrame(resolve));
      await new Promise(resolve => requestAnimationFrame(resolve));
      setAppReady(true);
    };
    signalReady();
  }, []);

  const handleSplashComplete = useCallback(() => {
    setSplashHiding(true);
    setTimeout(() => setSplashVisible(false), 450);
  }, []);

  // ── Bible Verses ──────────────────────────────────────────────────────────
  const [bibleVersesEnabled, setBibleVersesEnabledState] = useState(false);

  useEffect(() => {
    loadSettings()
      .then((s) => {
        if (s.bible_verses_enabled !== undefined) {
          setBibleVersesEnabledState(s.bible_verses_enabled);
        }
      })
      .catch(console.error);
  }, []);

  const setBibleVersesEnabled = useCallback((v: boolean) => {
    setBibleVersesEnabledState(v);
    void saveSettingsToDb({ bible_verses_enabled: v });
  }, []);

  // ── Teacher Mode ──────────────────────────────────────────────────────────
  // `enabled` is the single source of truth — sidebar is visible iff enabled.
  const [teacherEnabled, setTeacherEnabledState] = useState(false);
  const [focusedItem, setFocusedItem] = useState<TeacherFocusItem | null>(null);

  // Highlight state for cross-tab MITRE card animation
  const [mitreHighlightId, setMitreHighlightId] = useState<string | null>(null);

  // Load from DB on mount
  useEffect(() => {
    loadTeacherSettings()
      .then((s) => setTeacherEnabledState(s.enabled))
      .catch(console.error);
  }, []);

  // Single setter — updates state + DB, clears focus when disabling
  const setEnabled = useCallback((v: boolean) => {
    setTeacherEnabledState(v);
    if (!v) setFocusedItem(null);
    void saveTeacherSettings({ enabled: v });
  }, []);

  const focus = useCallback((item: TeacherFocusItem) => {
    setFocusedItem(item);
  }, []);

  const blur = useCallback(() => {
    setFocusedItem(null);
  }, []);

  const teacherCtx: TeacherModeContextValue = {
    enabled: teacherEnabled,
    setEnabled,
    focusedItem,
    focus,
    blur,
  };

  // ── MITRE cross-tab navigation ────────────────────────────────────────────
  const navigateToMitre = useCallback((techId: string) => {
    setActiveTab("mitre");
    setMitreHighlightId(techId);
    setTimeout(() => setMitreHighlightId(null), 2000);

    // When teacher mode is on, also load the technique into the sidebar
    if (teacherEnabled) {
      const parentId = techId.split(".")[0];
      const tech = result?.mitre_techniques?.find((t) => t.technique_id === parentId);
      if (tech) {
        focus({
          type: "mitre",
          techniqueId: techId,
          techniqueName: tech.technique_name,
          tactic: tech.tactic,
        });
      }
    }
  }, [teacherEnabled, focus, result]);

  const fileLoaded = !!result && !isLoading;

  React.useEffect(() => {
    if (result) setActiveTab("overview");
  }, [result?.file_info.path]);

  const fileName = result?.file_info.path
    ? result.file_info.path.split(/[\\/]/).pop() ?? ""
    : "";

  return (
    <TeacherModeContext.Provider value={teacherCtx}>
      <div
        data-theme={theme}
        style={{
          height: "100vh",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          background: "var(--bg-base)",
          color: "var(--text-primary)",
        }}
      >
        {splashVisible && (
          <SplashScreen
            onComplete={handleSplashComplete}
            className={splashHiding ? "splash-hiding" : ""}
            appReady={appReady}
          />
        )}
        <TopBar
          fileName={fileName}
          fileSize={result?.file_info.size_bytes ?? null}
          theme={theme}
          onToggleTheme={toggleTheme}
          onNewFile={() => { reset(); setActiveTab("overview"); }}
          onExport={fileLoaded ? result : null}
          onSettings={() => setShowSettings(true)}
        />

        {fileLoaded ? (
          <>
            <TabNav
              active={activeTab}
              onChange={setActiveTab}
              badges={(id) => tabHasBadge(id, result)}
            />
            {/*
              Push layout: main area is a flex row.
              TeacherSidebar is a flex sibling — it transitions its width
              between 0 and 280px so the tab content naturally shrinks/grows.
            */}
            <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "row" }}>
              <main style={{ flex: 1, overflow: "hidden", position: "relative" }}>
                <Suspense fallback={<TabFallback />}>
                  {activeTab === "overview"  && <OverviewTab  result={result} riskScore={riskScore} onMitreNavigate={navigateToMitre} />}
                  {activeTab === "entropy"   && <EntropyTab   result={result} />}
                  {activeTab === "imports"   && (
                    <ImportsTab
                      result={result}
                      onMitreNavigate={navigateToMitre}
                    />
                  )}
                  {activeTab === "sections"  && <SectionsTab  result={result} />}
                  {activeTab === "strings"   && <StringsTab   result={result} />}
                  {activeTab === "security"  && <SecurityTab  result={result} />}
                  {activeTab === "mitre"     && (
                    <MitreTab
                      result={result}
                      highlightId={mitreHighlightId}
                    />
                  )}
                </Suspense>
              </main>
              {/* Sidebar: always in DOM when file loaded; width transitions 0↔280 */}
              <TeacherSidebar />
            </div>
          </>
        ) : (
          <DropZone
            isLoading={isLoading}
            error={error}
            onFileDrop={analyse}
            onPickFile={analyse}
          />
        )}

        {bibleVersesEnabled && <BibleVerseBar />}

        {showSettings && (
          <SettingsModal
            theme={theme}
            onToggleTheme={toggleTheme}
            fontSize={fontSize}
            onSetFontSize={setFontSize}
            bibleVersesEnabled={bibleVersesEnabled}
            onSetBibleVerses={setBibleVersesEnabled}
            onClose={() => setShowSettings(false)}
          />
        )}
      </div>
    </TeacherModeContext.Provider>
  );
}
