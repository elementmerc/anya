import React, { Suspense, useState, lazy, useEffect, useCallback, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { SplashScreen } from "@/components/SplashScreen";
import { Installer } from "@/components/Installer";
import { Uninstaller } from "@/components/Uninstaller";
import { useAnalysis } from "@/hooks/useAnalysis";
import { useTheme } from "@/hooks/useTheme";
import { useFontSize } from "@/hooks/useFontSize";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import { TeacherModeContext, type TeacherModeContextValue, type TeacherFocusItem } from "@/hooks/useTeacherMode";
import { loadTeacherSettings, saveTeacherSettings, loadSettings, saveSettingsToDb, isGuidedTourCompleted, markGuidedTourCompleted } from "@/lib/db";
import { getThresholds, openFolderPicker, openFilePicker, analyzeDirectory, onBatchStarted, onBatchFileResult, onBatchComplete, pollDirectory, exportJson, saveJsonPicker, onFileDrop } from "@/lib/tauri-bridge";
import { BibleVerseBar } from "@/components/BibleVerseBar";
import { ToastProvider } from "@/components/Toast";
import DropZone from "@/components/DropZone";
import GuidedTour from "@/components/GuidedTour";
import TopBar from "@/components/TopBar";
import TabNav from "@/components/TabNav";
import SettingsModal from "@/components/SettingsModal";
import TeacherSidebar from "@/components/TeacherSidebar";
import BatchSidebar from "@/components/BatchSidebar";
import BatchDashboard from "@/components/BatchDashboard";
import KeyboardShortcutsOverlay from "@/components/KeyboardShortcutsOverlay";
import CompareView from "@/components/CompareView";
import type { TabName, AnalysisResult, ThresholdConfig, BatchState } from "@/types/analysis";

interface PinnedFinding {
  type: string;
  label: string;
  detail: string;
}

// Lazy-load tab components (code splitting)
import HomeView from "@/components/HomeView";
const OverviewTab  = lazy(() => import("@/components/tabs/OverviewTab"));
const IdentityTab  = lazy(() => import("@/components/tabs/IdentityTab"));
const EntropyTab   = lazy(() => import("@/components/tabs/EntropyTab"));
const ImportsTab   = lazy(() => import("@/components/tabs/ImportsTab"));
const SectionsTab  = lazy(() => import("@/components/tabs/SectionsTab"));
const StringsTab   = lazy(() => import("@/components/tabs/StringsTab"));
const SecurityTab  = lazy(() => import("@/components/tabs/SecurityTab"));
const MitreTab     = lazy(() => import("@/components/tabs/MitreTab"));
const FormatAnalysisTab = lazy(() => import("@/components/tabs/FormatAnalysisTab"));

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
  if (!result) return false;
  // Identity tab badges for any file type
  if (id === "identity") return !!result.ksd_match;
  // Format tab: badge if any format-specific analysis found suspicious content
  if (id === "format") return !!(
    result.javascript_analysis?.has_eval ||
    result.powershell_analysis?.has_encoded_command ||
    result.powershell_analysis?.has_amsi_bypass ||
    result.vbscript_analysis?.has_shell_exec ||
    result.html_analysis?.has_hidden_iframes ||
    result.xml_analysis?.has_external_entities ||
    result.ole_analysis?.has_auto_execute ||
    result.rtf_analysis?.contains_pe_bytes ||
    result.zip_analysis?.has_double_extensions ||
    result.lnk_analysis?.has_suspicious_target ||
    result.iso_analysis?.has_autorun
  );
  // MITRE badges work for all file types
  if (id === "mitre") return (result.mitre_techniques?.length ?? 0) > 0;
  // Security tab: YARA matches badge for all file types
  if (id === "security") return (result.yara_matches?.length ?? 0) > 0 || !!result.ksd_match;
  if (!result.pe_analysis) return false;
  const pe = result.pe_analysis;
  switch (id) {
    case "imports":  return pe.imports.suspicious_api_count > 0 || pe.anti_analysis.length > 0;
    case "sections": return pe.sections.some((s) => s.is_wx);
    case "entropy":  return pe.sections.some((s) => s.entropy > 7.0);
    default:         return false;
  }
}

const INITIAL_BATCH: BatchState = {
  active: false,
  directoryPath: null,
  recursive: false,
  totalFiles: 0,
  results: [],
  selectedIndex: null,
  isRunning: false,
  sidebarCollapsed: false,
  batchId: 0,
};

export default function App() {
  const { result, riskScore, isLoading, error, analyse, reset } = useAnalysis();
  const { theme, toggleTheme, setTheme } = useTheme();
  const { fontSize, setFontSize } = useFontSize();
  const [activeTab, setActiveTab] = useState<TabName>("overview");
  const [showSettings, setShowSettings] = useState(false);
  const [thresholds, setThresholds] = useState<ThresholdConfig>({
    suspicious_entropy: 5.0,
    packed_entropy: 7.0,
    suspicious_score: 40,
    malicious_score: 70,
  });

  const [batchState, setBatchState] = useState<BatchState>(INITIAL_BATCH);

  // ── Guided tour (first analysis) ──────────────────────────────────────────
  const [showTour, setShowTour] = useState(false);
  const [tourEligible, setTourEligible] = useState(false);

  useEffect(() => {
    isGuidedTourCompleted().then((done) => {
      if (!done) setTourEligible(true);
    }).catch(() => setTourEligible(true));
  }, []);

  useEffect(() => {
    if (result && tourEligible && !showTour) {
      setShowTour(true);
    }
  }, [result, tourEligible]);

  const handleTourComplete = useCallback(() => {
    setShowTour(false);
    setTourEligible(false);
    markGuidedTourCompleted().catch(() => {});
  }, []);

  // ── C7: Keyboard shortcuts ──────────────────────────────────────────────
  const [showShortcuts, setShowShortcuts] = useState(false);

  // ── C8: Compare mode ────────────────────────────────────────────────────
  const [compareMode, setCompareMode] = useState(false);

  // ── C11: Tab order (drag-and-drop reorder) ──────────────────────────────
  const [tabOrder, setTabOrder] = useState<TabName[]>(["overview", "entropy", "imports", "sections", "strings", "security", "mitre"]);

  // ── C12: Pinned findings ────────────────────────────────────────────────
  const [pinnedFindings, setPinnedFindings] = useState<PinnedFinding[]>([]);

  const handlePin = useCallback((finding: PinnedFinding) => {
    setPinnedFindings((prev) => {
      // Don't add duplicates
      if (prev.some((f) => f.label === finding.label && f.detail === finding.detail)) return prev;
      return [...prev, finding];
    });
  }, []);

  useEffect(() => {
    getThresholds().then(setThresholds).catch(() => {});
  }, []);

  // ── Global drag-and-drop — works even when viewing results ────────────────
  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | null = null;
    onFileDrop((paths) => {
      if (cancelled) return;
      const path = paths[0];
      if (path) {
        // Reset any batch/compare state and analyse the dropped file
        setBatchState(INITIAL_BATCH);
        setCompareMode(false);
        setActiveTab("overview");
        analyse(path);
      }
    }).then((fn) => { if (!cancelled) unlisten = fn; else fn(); });
    return () => { cancelled = true; unlisten?.(); };
  }, [analyse]);

  // ── Batch event listeners ─────────────────────────────────────────────────
  useEffect(() => {
    if (!batchState.active) return;

    const currentBatchId = batchState.batchId;
    const unlisteners: Array<() => void> = [];

    onBatchStarted((payload) => {
      if (payload.batch_id !== currentBatchId) return;
      setBatchState((prev) => ({ ...prev, totalFiles: payload.total_files }));
    }).then((unlisten) => unlisteners.push(unlisten));

    onBatchFileResult((payload) => {
      if (payload.batch_id !== currentBatchId) return;
      setBatchState((prev) => ({
        ...prev,
        results: prev.results.some((r) => r.filePath === payload.file_path)
          ? prev.results  // skip duplicate
          : [...prev.results, {
            index: payload.index,
            filePath: payload.file_path,
            fileName: payload.file_name,
            result: payload.result,
            riskScore: payload.risk_score,
            verdict: payload.verdict,
            error: payload.error,
          }],
      }));
    }).then((unlisten) => unlisteners.push(unlisten));

    onBatchComplete((payload) => {
      if (payload.batch_id !== currentBatchId) return;
      setBatchState((prev) => ({ ...prev, isRunning: false }));
    }).then((unlisten) => unlisteners.push(unlisten));

    return () => { unlisteners.forEach((u) => u()); };
  }, [batchState.active, batchState.batchId]);

  // Poll directory for file changes every 5 seconds when batch is idle
  useEffect(() => {
    if (!batchState.active || batchState.isRunning || !batchState.directoryPath) return;

    const interval = setInterval(async () => {
      try {
        const currentFiles = await pollDirectory(batchState.directoryPath!, batchState.recursive);
        const knownPaths = new Set(batchState.results.map((r) => r.filePath));
        const currentSet = new Set(currentFiles);

        // Detect removed files
        const removedPaths = batchState.results.filter((r) => !currentSet.has(r.filePath));
        if (removedPaths.length > 0) {
          setBatchState((prev) => ({
            ...prev,
            results: prev.results.filter((r) => currentSet.has(r.filePath)),
            totalFiles: prev.totalFiles - removedPaths.length,
            selectedIndex: prev.selectedIndex !== null && removedPaths.some((r) => r.index === prev.selectedIndex) ? null : prev.selectedIndex,
          }));
        }

        // Detect new files — trigger analysis for them
        const newFiles = currentFiles.filter((f) => !knownPaths.has(f));
        if (newFiles.length > 0) {
          const id = Date.now();
          setBatchState((prev) => ({
            ...prev,
            isRunning: true,
            batchId: id,
            totalFiles: prev.totalFiles + newFiles.length,
          }));
          await analyzeDirectory(batchState.directoryPath!, batchState.recursive, id);
        }
      } catch {
        // Silently ignore polling errors (directory may have been removed)
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [batchState.active, batchState.isRunning, batchState.directoryPath, batchState.recursive, batchState.results]);

  // ── Launch mode + first-run detection ────────────────────────────────────────
  const [launchMode, setLaunchMode] = useState<"normal" | "uninstall" | null>(null);
  const [firstRun, setFirstRun] = useState<boolean | null>(null);

  useEffect(() => {
    invoke<string>("get_launch_mode")
      .then((mode) => setLaunchMode(mode as "normal" | "uninstall"))
      .catch(() => setLaunchMode("normal"));
  }, []);

  useEffect(() => {
    if (launchMode !== "normal") return;
    invoke<string>("is_first_run")
      .then((status) => setFirstRun(status === "first_run"))
      .catch(() => setFirstRun(false));
  }, [launchMode]);

  const handleInstallerComplete = useCallback(
    (prefs: { darkTheme: boolean; teacherMode: boolean; installPath: string }) => {
      setTheme(prefs.darkTheme ? "dark" : "light");
      setTeacherEnabledState(prefs.teacherMode);
      void saveTeacherSettings({ enabled: prefs.teacherMode });
      void saveSettingsToDb({ theme: prefs.darkTheme ? "dark" : "light" });
      setFirstRun(false);
    },
    [setTheme]
  );

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

  // ── Batch handlers ──────────────────────────────────────────────────────
  const handleBatchAnalysis = useCallback(async () => {
    const folder = await openFolderPicker();
    if (!folder) return;
    reset();
    const id = Date.now();
    setBatchState({
      ...INITIAL_BATCH,
      active: true,
      directoryPath: folder,
      isRunning: true,
      batchId: id,
    });
    setActiveTab("overview");
    await analyzeDirectory(folder, false, id);
  }, [reset]);

  const handleToggleRecursive = useCallback(() => {
    if (!batchState.directoryPath) return;
    const newRecursive = !batchState.recursive;

    if (!newRecursive) {
      // Turning OFF recursive: filter results to top-level only (no re-analysis)
      const dirPrefix = batchState.directoryPath.endsWith("/")
        ? batchState.directoryPath
        : batchState.directoryPath + "/";
      const topLevel = batchState.results.filter((r) => {
        const rel = r.filePath.slice(dirPrefix.length);
        return !rel.includes("/");
      });
      setBatchState((prev) => ({
        ...prev,
        recursive: false,
        results: topLevel,
        totalFiles: topLevel.length,
        selectedIndex: null,
      }));
    } else {
      // Turning ON recursive: re-scan, backend finds new files
      // Frontend will deduplicate by filePath
      const id = Date.now();
      setBatchState((prev) => ({
        ...prev,
        recursive: true,
        isRunning: true,
        batchId: id,
      }));
      analyzeDirectory(batchState.directoryPath, true, id);
    }
  }, [batchState.directoryPath, batchState.recursive, batchState.results]);

  // ── Derived values ─────────────────────────────────────────────────────
  const batchSelectedResult = batchState.active && batchState.selectedIndex !== null
    ? batchState.results.find((r) => r.index === batchState.selectedIndex) ?? null
    : null;

  const activeResult = batchSelectedResult?.result ?? result;
  const activeRiskScore = batchSelectedResult?.riskScore ?? riskScore;

  const fileLoaded = !!result && !isLoading;

  React.useEffect(() => {
    if (result) {
      setActiveTab("overview");
      setPinnedFindings([]);  // Clear pinned findings on new analysis
      // Dynamically add/remove conditional tabs based on content
      const hasIdentity = result.ksd_match || result.pe_analysis?.dotnet_metadata;
      const hasFormat = !!(
        result.javascript_analysis || result.powershell_analysis ||
        result.vbscript_analysis || result.shell_script_analysis ||
        result.python_analysis || result.ole_analysis || result.rtf_analysis ||
        result.zip_analysis || result.html_analysis || result.xml_analysis ||
        result.image_analysis || result.lnk_analysis || result.iso_analysis ||
        result.cab_analysis || result.msi_analysis ||
        result.pdf_analysis || result.office_analysis
      );
      setTabOrder((prev) => {
        let tabs: TabName[] = prev.filter((t) => t !== "identity" && t !== "format");
        if (hasIdentity) {
          const idx = tabs.indexOf("overview");
          tabs = [...tabs.slice(0, idx + 1), "identity" as TabName, ...tabs.slice(idx + 1)];
        }
        if (hasFormat) {
          const mitreIdx = tabs.indexOf("mitre");
          if (mitreIdx >= 0) {
            tabs = [...tabs.slice(0, mitreIdx), "format" as TabName, ...tabs.slice(mitreIdx)];
          } else {
            tabs.push("format");
          }
        }
        return tabs;
      });
    }
  }, [result?.file_info.path]);

  const fileName = result?.file_info.path
    ? result.file_info.path.split(/[\\/]/).pop() ?? ""
    : "";

  // ── C7: Keyboard shortcuts ──────────────────────────────────────────────
  const TAB_NAMES: TabName[] = tabOrder;

  const shortcutActions = useMemo(() => ({
    openFile: () => {
      openFilePicker().then((picked) => {
        const path = Array.isArray(picked) ? picked[0] : picked;
        if (path) analyse(path);
      });
    },
    batchAnalysis: () => void handleBatchAnalysis(),
    switchTab: (index: number) => {
      if (index >= 0 && index < TAB_NAMES.length) setActiveTab(TAB_NAMES[index]);
    },
    toggleTeacher: () => setEnabled(!teacherEnabled),
    exportJson: () => {
      if (fileLoaded && result) {
        saveJsonPicker().then((path) => {
          if (path) exportJson(result, path);
        });
      }
    },
    closeModal: () => {
      if (showShortcuts) setShowShortcuts(false);
      else if (showSettings) setShowSettings(false);
    },
    showShortcuts: () => setShowShortcuts((v) => !v),
  }), [TAB_NAMES, teacherEnabled, setEnabled, fileLoaded, result, showShortcuts, showSettings, analyse, handleBatchAnalysis]);

  useKeyboardShortcuts(shortcutActions, !splashVisible && launchMode === "normal");

  // Launch mode / first-run gates
  if (launchMode === null) return null;
  if (launchMode === "uninstall") return <Uninstaller />;
  if (firstRun === null) return null;
  if (firstRun) return <Installer onComplete={handleInstallerComplete} />;

  return (
    <ToastProvider>
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
            theme={theme}
          />
        )}
        <TopBar
          fileName={
            batchState.active
              ? batchState.selectedIndex !== null && batchSelectedResult
                ? batchSelectedResult.fileName
                : batchState.directoryPath ?? ""
              : fileName
          }
          fileSize={
            batchState.active
              ? batchState.selectedIndex !== null && batchSelectedResult?.result
                ? batchSelectedResult.result.file_info.size_bytes
                : null
              : result?.file_info.size_bytes ?? null
          }
          theme={theme}
          onToggleTheme={toggleTheme}
          onNewFile={() => { reset(); setBatchState(INITIAL_BATCH); setCompareMode(false); setActiveTab("overview"); }}
          onExport={fileLoaded ? result : null}
          onSaveToCase={fileLoaded ? result : null}
          onSettings={() => setShowSettings(true)}
          onBatchAnalysis={handleBatchAnalysis}
          onCompare={() => { reset(); setBatchState(INITIAL_BATCH); setCompareMode(true); }}
          onGoHome={() => { reset(); setBatchState(INITIAL_BATCH); setCompareMode(false); setActiveTab("overview"); }}
        />

        {compareMode ? (
          <CompareView onClose={() => setCompareMode(false)} />
        ) : batchState.active ? (
          <>
            <TabNav
              active={activeTab}
              onChange={setActiveTab}
              badges={(id) => tabHasBadge(id, activeResult)}
              disabled={batchState.selectedIndex === null}
              tabOrder={tabOrder}
              onTabOrderChange={setTabOrder}
            />
            <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
              <BatchSidebar
                state={batchState}
                onSelectFile={(idx) => setBatchState((prev) => ({ ...prev, selectedIndex: idx }))}
                onDeselectFile={() => setBatchState((prev) => ({ ...prev, selectedIndex: null }))}
                onToggleRecursive={handleToggleRecursive}
                onToggleCollapse={() => setBatchState((prev) => ({ ...prev, sidebarCollapsed: !prev.sidebarCollapsed }))}
              />
              <main style={{ flex: 1, overflow: "auto", position: "relative" }}>
                {batchState.selectedIndex !== null && batchSelectedResult?.result ? (
                  <Suspense fallback={<TabFallback />}>
                    {activeTab === "overview"  && <OverviewTab  result={activeResult!} riskScore={activeRiskScore} onMitreNavigate={navigateToMitre} pinnedFindings={pinnedFindings} onPin={handlePin} onUnpin={(i) => setPinnedFindings((prev) => prev.filter((_, j) => j !== i))} theme={theme} />}
                    {activeTab === "identity"  && <IdentityTab  result={activeResult!} />}
                    {activeTab === "entropy"   && <EntropyTab   result={activeResult!} suspiciousEntropy={thresholds.suspicious_entropy} packedEntropy={thresholds.packed_entropy} />}
                    {activeTab === "imports"   && (
                      <ImportsTab
                        result={activeResult!}
                        onMitreNavigate={navigateToMitre}
                        onPin={handlePin}
                      />
                    )}
                    {activeTab === "sections"  && <SectionsTab  result={activeResult!} suspiciousEntropy={thresholds.suspicious_entropy} packedEntropy={thresholds.packed_entropy} onPin={handlePin} />}
                    {activeTab === "strings"   && <StringsTab   result={activeResult!} onPin={handlePin} />}
                    {activeTab === "security"  && <SecurityTab  result={activeResult!} packedEntropy={thresholds.packed_entropy} />}
                    {activeTab === "format"    && <FormatAnalysisTab result={activeResult!} />}
                    {activeTab === "mitre"     && (
                      <MitreTab
                        result={activeResult!}
                        highlightId={mitreHighlightId}
                        onPin={handlePin}
                      />
                    )}
                  </Suspense>
                ) : (
                  <BatchDashboard state={batchState} theme={theme} onNodeClick={(idx) => setBatchState((prev) => ({ ...prev, selectedIndex: prev.selectedIndex === idx ? null : idx }))} />
                )}
              </main>
              <TeacherSidebar />
            </div>
          </>
        ) : fileLoaded ? (
          <>
            <TabNav
              active={activeTab}
              onChange={setActiveTab}
              badges={(id) => tabHasBadge(id, activeResult)}
              tabOrder={tabOrder}
              onTabOrderChange={setTabOrder}
            />
            {/*
              Push layout: main area is a flex row.
              TeacherSidebar is a flex sibling — it transitions its width
              between 0 and 280px so the tab content naturally shrinks/grows.
            */}
            <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "row" }}>
              <main style={{ flex: 1, overflow: "hidden", position: "relative" }}>
                <Suspense fallback={<TabFallback />}>
                  {activeTab === "overview"  && <OverviewTab  result={activeResult!} riskScore={activeRiskScore} onMitreNavigate={navigateToMitre} pinnedFindings={pinnedFindings} onPin={handlePin} onUnpin={(i) => setPinnedFindings((prev) => prev.filter((_, j) => j !== i))} theme={theme} />}
                  {activeTab === "identity"  && <IdentityTab  result={activeResult!} />}
                  {activeTab === "entropy"   && <EntropyTab   result={activeResult!} suspiciousEntropy={thresholds.suspicious_entropy} packedEntropy={thresholds.packed_entropy} />}
                  {activeTab === "imports"   && (
                    <ImportsTab
                      result={activeResult!}
                      onMitreNavigate={navigateToMitre}
                      onPin={handlePin}
                    />
                  )}
                  {activeTab === "sections"  && <SectionsTab  result={activeResult!} suspiciousEntropy={thresholds.suspicious_entropy} packedEntropy={thresholds.packed_entropy} onPin={handlePin} />}
                  {activeTab === "strings"   && <StringsTab   result={activeResult!} onPin={handlePin} />}
                  {activeTab === "security"  && <SecurityTab  result={activeResult!} packedEntropy={thresholds.packed_entropy} />}
                  {activeTab === "format"    && <FormatAnalysisTab result={activeResult!} />}
                  {activeTab === "mitre"     && (
                    <MitreTab
                      result={activeResult!}
                      highlightId={mitreHighlightId}
                      onPin={handlePin}
                    />
                  )}
                </Suspense>
              </main>
              {/* Sidebar: always in DOM when file loaded; width transitions 0↔280 */}
              <TeacherSidebar />
            </div>
          </>
        ) : (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "auto" }}>
            <HomeView onOpenFile={analyse} isLoading={isLoading} />
            <DropZone
              isLoading={isLoading}
              error={error}
              onPickFile={analyse}
            />
          </div>
        )}

        {bibleVersesEnabled && <BibleVerseBar />}

        <GuidedTour active={showTour} onComplete={handleTourComplete} />

        {showSettings && (
          <SettingsModal
            theme={theme}
            onToggleTheme={toggleTheme}
            fontSize={fontSize}
            onSetFontSize={setFontSize}
            bibleVersesEnabled={bibleVersesEnabled}
            onSetBibleVerses={setBibleVersesEnabled}
            onClose={() => setShowSettings(false)}
            onThresholdsChange={setThresholds}
          />
        )}

        <KeyboardShortcutsOverlay open={showShortcuts} onClose={() => setShowShortcuts(false)} />
      </div>
    </TeacherModeContext.Provider>
    </ToastProvider>
  );
}
