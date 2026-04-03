import React, { Suspense, useState, useRef, lazy, useEffect, useCallback, useMemo } from "react";
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
import { initAllExplanations } from "@/lib/apiDescriptions";
import { getThresholds, openFolderPicker, openFilePicker, analyzeDirectory, onBatchStarted, onBatchFileResult, onBatchComplete, pollDirectory, exportJson, saveJsonPicker, onFileDrop, getBatchGraphData } from "@/lib/tauri-bridge";
import type { GraphData } from "@/types/analysis";
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
const SingleFileGraph = lazy(() => import("@/components/SingleFileGraph"));

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
  // Graph badge: 3+ suspicious APIs or classified strings
  if (id === "graph") return (result.pe_analysis?.imports?.suspicious_api_count ?? 0) >= 3
    || (result.strings?.classified?.filter((s) => s.category !== "Plain")?.length ?? 0) >= 3;
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
  const [batchGraphData, setBatchGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [batchSearchQuery, setBatchSearchQuery] = useState(""); // passed to BatchSidebar + BatchGraph

  // ── Guided tour (first analysis) ──────────────────────────────────────────
  const [showTour, setShowTour] = useState(false);
  const [tourEligible, setTourEligible] = useState(false);

  useEffect(() => {
    isGuidedTourCompleted().then((done) => {
      if (!done) setTourEligible(true);
    }).catch(() => setTourEligible(true));
    initAllExplanations();
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

  // ── Global drag-and-drop — files trigger single analysis, folders trigger batch ──
  const startBatchFromDrop = useCallback((folder: string) => {
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
    setTabOrder((prev) => prev.includes("graph") ? prev : [...prev, "graph"]);
    void analyzeDirectory(folder, false, id);
  }, [reset]);

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | null = null;
    onFileDrop(async (paths) => {
      if (cancelled || paths.length === 0) return;
      // Check if the dropped path is a directory
      try {
        const { stat } = await import("@tauri-apps/plugin-fs");
        const info = await stat(paths[0]);
        if (info.isDirectory) {
          startBatchFromDrop(paths[0]);
          return;
        }
      } catch {
        // stat failed — treat as file
      }
      // Single file analysis
      setBatchState(INITIAL_BATCH);
      setCompareMode(false);
      setActiveTab("overview");
      analyse(paths[0]);
    }).then((fn) => { if (!cancelled) unlisten = fn; else fn(); });
    return () => { cancelled = true; unlisten?.(); };
  }, [analyse, startBatchFromDrop]);

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

  // Load batch graph data when results change
  useEffect(() => {
    if (!batchState.active || batchState.results.length < 2) return;
    const validResults = batchState.results.filter((r) => r.result != null);
    getBatchGraphData(validResults.map((r) => r.result))
      .then((graphData) => {
        // Override node colors using the sidebar's verdict (single source of truth)
        const COLORS: Record<string, string> = { malicious: "#ef4444", suspicious: "#eab308", clean: "#22c55e", error: "#6b7280" };
        for (const node of graphData.nodes) {
          const batchResult = validResults[node.id];
          if (batchResult) {
            node.color = COLORS[batchResult.verdict] ?? "#22c55e";
            node.verdict = batchResult.verdict.toUpperCase();
          }
        }
        setBatchGraphData(graphData);
      })
      .catch(() => {});
  }, [batchState.active, batchState.results.length]);

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
    setTabOrder((prev) => prev.includes("graph") ? prev : [...prev, "graph"]);
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
        let tabs: TabName[] = prev.filter((t) => t !== "identity" && t !== "format" && t !== "graph");
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
        // Graph tab always available — placed after MITRE
        tabs.push("graph");
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

  // ── Tab keep-alive: visited tabs stay mounted (preserves scroll/search state) ──
  const [visitedTabs, setVisitedTabs] = useState<Set<TabName>>(new Set(["overview"]));
  const prevResultRef = useRef(activeResult);
  useEffect(() => {
    // Reset visited tabs when analysing a new file
    if (activeResult && activeResult !== prevResultRef.current) {
      prevResultRef.current = activeResult;
      setVisitedTabs(new Set([activeTab]));
    }
  }, [activeResult, activeTab]);
  useEffect(() => {
    setVisitedTabs((prev) => {
      if (prev.has(activeTab)) return prev;
      return new Set([...prev, activeTab]);
    });
  }, [activeTab]);

  const renderTabContent = useCallback(() => {
    if (!activeResult) return null;
    const tabs: { id: TabName; el: React.ReactNode }[] = [
      { id: "overview",  el: <OverviewTab  result={activeResult} riskScore={activeRiskScore} onMitreNavigate={navigateToMitre} pinnedFindings={pinnedFindings} onPin={handlePin} onUnpin={(i) => setPinnedFindings((prev) => prev.filter((_, j) => j !== i))} theme={theme} /> },
      { id: "identity",  el: <IdentityTab  result={activeResult} /> },
      { id: "entropy",   el: <EntropyTab   result={activeResult} suspiciousEntropy={thresholds.suspicious_entropy} packedEntropy={thresholds.packed_entropy} /> },
      { id: "imports",   el: <ImportsTab   result={activeResult} onMitreNavigate={navigateToMitre} onPin={handlePin} /> },
      { id: "sections",  el: <SectionsTab  result={activeResult} suspiciousEntropy={thresholds.suspicious_entropy} packedEntropy={thresholds.packed_entropy} onPin={handlePin} /> },
      { id: "strings",   el: <StringsTab   result={activeResult} onPin={handlePin} /> },
      { id: "security",  el: <SecurityTab  result={activeResult} packedEntropy={thresholds.packed_entropy} /> },
      { id: "format",    el: <FormatAnalysisTab result={activeResult} /> },
      { id: "mitre",     el: <MitreTab     result={activeResult} highlightId={mitreHighlightId} onPin={handlePin} /> },
      { id: "graph",     el: <SingleFileGraph result={activeResult} theme={theme} /> },
    ];
    return (
      <>
        {/* Keep-alive tabs (preserve scroll/state) */}
        {tabs.filter((t) => visitedTabs.has(t.id) && t.id !== "graph").map((t) => (
          <div
            key={t.id}
            className={t.id === activeTab ? "tab-content-enter" : undefined}
            style={{
              display: t.id === activeTab ? "flex" : "none",
              flexDirection: "column",
              flex: 1,
              minHeight: 0,
              overflow: "auto",
            }}
          >
            {t.el}
          </div>
        ))}
        {/* Graph tab: mount/unmount (not keep-alive) so canvas gets correct dimensions on mount */}
        {activeTab === "graph" && (
          <div className="tab-content-enter" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, overflow: "hidden" }}>
            {tabs.find((t) => t.id === "graph")?.el}
          </div>
        )}
      </>
    );
  }, [activeTab, activeResult, activeRiskScore, navigateToMitre, pinnedFindings, handlePin, theme, thresholds, mitreHighlightId, visitedTabs]);

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
              disabledFn={batchState.selectedIndex === null ? (id) => id !== "graph" && id !== "overview" : undefined}
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
                searchQuery={batchSearchQuery}
                onSearchChange={setBatchSearchQuery}
              />
              <main style={{ flex: 1, overflow: activeTab === "graph" ? "hidden" : "auto", display: "flex", flexDirection: "column", minHeight: 0 }}>
                {batchState.selectedIndex !== null && batchSelectedResult?.result ? (
                  <Suspense fallback={<TabFallback />}>
                    {renderTabContent()}
                  </Suspense>
                ) : (
                  <BatchDashboard
                    state={batchState}
                    theme={theme}
                    graphData={batchGraphData}
                    onNodeClick={(idx) => setBatchState((prev) => ({ ...prev, selectedIndex: idx }))}
                    searchQuery={batchSearchQuery}
                  />
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
              <main style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column", minHeight: 0 }}>
                <Suspense fallback={<TabFallback />}>
                  {renderTabContent()}
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
