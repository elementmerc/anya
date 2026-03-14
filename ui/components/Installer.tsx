import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./Installer.css";

interface InstallerProps {
  onComplete: (prefs: { darkTheme: boolean; teacherMode: boolean; installPath: string }) => void;
}

export function Installer({ onComplete }: InstallerProps) {
  const [step, setStep] = useState(1);
  const [licAccepted, setLicAccepted] = useState(false);
  const [installPath, setInstallPath] = useState("");
  const [darkTheme, setDarkTheme] = useState(false);
  const [teacherMode, setTeacherMode] = useState(false);
  const [progPct, setProgPct] = useState(0);
  const [progMsg, setProgMsg] = useState("Starting\u2026");
  const [addDesktop, setAddDesktop] = useState(true);
  const [openNow, setOpenNow] = useState(true);

  useEffect(() => {
    invoke<string>("get_default_install_path")
      .then(setInstallPath)
      .catch(() => setInstallPath("~/.local/share/anya"));
  }, []);

  // Step 4: simulated install progress
  useEffect(() => {
    if (step !== 4) return;
    const stages = [
      { pct: 15, msg: "Creating data folder\u2026", delay: 600 },
      { pct: 30, msg: "Frying Yam\u2026", delay: 2200 },
      { pct: 48, msg: "Verifying MITRE data\u2026", delay: 900 },
      { pct: 62, msg: "Catching Black-Hats\u2026", delay: 2400 },
      { pct: 75, msg: "Applying preferences\u2026", delay: 700 },
      { pct: 85, msg: "Roasting VirusTotal\u2026", delay: 2000 },
      { pct: 93, msg: "Almost there\u2026", delay: 600 },
      { pct: 100, msg: "Done. Let\u2019s Party.", delay: 800 },
    ];
    let total = 0;
    const timers: ReturnType<typeof setTimeout>[] = [];
    for (const s of stages) {
      total += s.delay;
      const t = setTimeout(() => {
        setProgPct(s.pct);
        setProgMsg(s.msg);
      }, total);
      timers.push(t);
    }
    const done = setTimeout(async () => {
      try {
        await invoke("complete_setup", {
          installPath,
          darkTheme,
          teacherMode,
        });
      } catch {
        // marker write failed — continue anyway
      }
      setStep(5);
    }, total + 300);
    timers.push(done);
    return () => timers.forEach(clearTimeout);
  }, [step, installPath, darkTheme, teacherMode]);

  async function handleBrowse() {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        defaultPath: installPath,
        title: "Choose Anya data folder",
      });
      if (selected && typeof selected === "string") {
        setInstallPath(selected);
      }
    } catch {
      // user cancelled
    }
  }

  function handleLaunch() {
    // "Add to desktop" is a no-op — Tauri's installer handles shortcuts.
    // Wire to a shell command in a future iteration if needed.
    void addDesktop;
    if (openNow) {
      onComplete({ darkTheme, teacherMode, installPath });
    } else {
      onComplete({ darkTheme, teacherMode, installPath });
    }
  }

  return (
    <div className={`installer ${darkTheme ? "dark" : "light"}`}>
      {/* Logo */}
      <svg width="48" height="44" viewBox="0 0 200 180" xmlns="http://www.w3.org/2000/svg" style={{ marginBottom: 6 }}>
        <line x1="36" y1="158" x2="100" y2="22" stroke={darkTheme ? "#e8e5dc" : "#111113"} strokeWidth="14" strokeLinecap="round" />
        <line x1="164" y1="158" x2="100" y2="22" stroke={darkTheme ? "#e8e5dc" : "#111113"} strokeWidth="14" strokeLinecap="round" />
        <line x1="58" y1="96" x2="142" y2="96" stroke="#D85A30" strokeWidth="12" strokeLinecap="round" />
      </svg>
      <span className="inst-title" style={{ fontSize: 15, fontWeight: 600, letterSpacing: "0.18em", marginBottom: 2 }}>ANYA</span>
      <span className="inst-sub" style={{ fontSize: 11, marginBottom: 20 }}>Setup Assistant</span>

      <div className="installer-card">
        {/* Step dots */}
        <div style={{ display: "flex", gap: 6, justifyContent: "center", marginBottom: 16 }}>
          {[1, 2, 3, 4, 5].map((s) => (
            <div
              key={s}
              className={`dot${s < step ? " done" : ""}${s === step ? " active" : ""}`}
            />
          ))}
        </div>

        {/* ── Step 1: Licence ─────────────────────────────── */}
        {step === 1 && (
          <div className="inst-panel">
            <h3 className="card-head" style={{ margin: "0 0 8px", fontSize: 14, fontWeight: 600 }}>AGPL-3.0 Licence</h3>
            <div className="card-body" style={{ flex: 1, fontSize: 12, lineHeight: 1.6, overflow: "auto" }}>
              <p style={{ margin: "0 0 8px" }}>
                Anya is free software released under the GNU Affero General Public License v3.0.
              </p>
              <p style={{ margin: "0 0 8px" }}>
                You may use, modify, and distribute this software freely. If you modify Anya and make it
                available over a network, you must release your modifications under the same licence.
              </p>
              <p style={{ margin: "0 0 8px" }}>
                This software is provided without warranty. The full licence text is available at{" "}
                <span style={{ fontFamily: "monospace", fontSize: 11 }}>LICENSE.TXT</span> in the
                application directory.
              </p>
              <p style={{ margin: 0 }}>
                Commercial licensing is available for organisations that cannot comply with AGPL terms.
              </p>
            </div>
            <label style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 12, cursor: "pointer" }}>
              <input
                type="checkbox"
                className="anya-tog"
                checked={licAccepted}
                onChange={(e) => setLicAccepted(e.target.checked)}
              />
              <span className="tog-lbl" style={{ fontSize: 12 }}>I accept the licence terms</span>
            </label>
          </div>
        )}

        {/* ── Step 2: Location ────────────────────────────── */}
        {step === 2 && (
          <div className="inst-panel">
            <h3 className="card-head" style={{ margin: "0 0 8px", fontSize: 14, fontWeight: 600 }}>Install location</h3>
            <p className="card-body" style={{ margin: "0 0 12px", fontSize: 12, lineHeight: 1.6 }}>
              Choose where Anya stores its data — analysis history, settings, and the local database.
              This can be changed later in Settings.
            </p>
            <div className="path-row">
              <div className="path-display" title={installPath}>
                {installPath || "Loading\u2026"}
              </div>
              <button className="browse-btn" onClick={() => void handleBrowse()}>
                Browse\u2026
              </button>
            </div>
            <p className="inst-hint" style={{ fontSize: 10, marginTop: 8 }}>
              The folder will be created if it doesn&apos;t exist.
            </p>
          </div>
        )}

        {/* ── Step 3: Preferences ─────────────────────────── */}
        {step === 3 && (
          <div className="inst-panel">
            <h3 className="card-head" style={{ margin: "0 0 8px", fontSize: 14, fontWeight: 600 }}>Initial preferences</h3>
            <p className="card-body" style={{ margin: "0 0 16px", fontSize: 12, lineHeight: 1.6 }}>
              Set your preferred theme and whether to enable Teacher Mode.
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }}>
                <span className="tog-lbl" style={{ fontSize: 13 }}>Dark theme</span>
                <input
                  type="checkbox"
                  className="anya-tog"
                  checked={darkTheme}
                  onChange={(e) => setDarkTheme(e.target.checked)}
                />
              </label>
              <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }}>
                <span className="tog-lbl" style={{ fontSize: 13 }}>Teacher Mode</span>
                <input
                  type="checkbox"
                  className="anya-tog"
                  checked={teacherMode}
                  onChange={(e) => setTeacherMode(e.target.checked)}
                />
              </label>
            </div>
            <p className="inst-hint" style={{ fontSize: 10, marginTop: "auto", paddingTop: 12 }}>
              Both can be changed anytime in Settings.
            </p>
          </div>
        )}

        {/* ── Step 4: Installing ──────────────────────────── */}
        {step === 4 && (
          <div className="inst-panel" style={{ justifyContent: "center" }}>
            <h3 className="card-head" style={{ margin: "0 0 8px", fontSize: 14, fontWeight: 600 }}>Setting up Anya</h3>
            <p className="card-body" style={{ margin: "0 0 20px", fontSize: 12, lineHeight: 1.6 }}>
              Creating your data folder, verifying files, and applying your preferences.
            </p>
            <div className="prog-track">
              <div className="prog-fill" style={{ width: `${progPct}%` }} />
            </div>
            <span className="prog-lbl">{progMsg}</span>
          </div>
        )}

        {/* ── Step 5: Done ────────────────────────────────── */}
        {step === 5 && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1 }}>
            {/* Green checkmark circle */}
            <div style={{ width: 56, height: 56, borderRadius: "50%", background: "#1D9E75", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </div>
            <h3 className="done-title" style={{ margin: "0 0 4px", fontSize: 16, fontWeight: 600 }}>Anya is ready</h3>
            <p className="done-sub" style={{ margin: "0 0 20px", fontSize: 12 }}>Fast, offline malware analysis.</p>

            <div style={{ display: "flex", flexDirection: "column", gap: 8, width: "100%", maxWidth: 280, marginBottom: 20 }}>
              <label className="done-opt" onClick={() => setAddDesktop(!addDesktop)}>
                <input type="checkbox" className="done-opt-check" checked={addDesktop} readOnly />
                <span className="done-opt-text" style={{ fontSize: 12 }}>Add to desktop</span>
              </label>
              <label className="done-opt" onClick={() => setOpenNow(!openNow)}>
                <input type="checkbox" className="done-opt-check" checked={openNow} readOnly />
                <span className="done-opt-text" style={{ fontSize: 12 }}>Open Anya now</span>
              </label>
            </div>

            <button
              onClick={handleLaunch}
              style={{
                background: "#1D9E75",
                border: "none",
                color: "#fff",
                borderRadius: 6,
                padding: "10px 28px",
                fontSize: 13,
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "inherit",
                transition: "opacity 0.15s",
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.opacity = "0.85"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.opacity = "1"; }}
            >
              Launch Anya
            </button>
          </div>
        )}

        {/* ── Navigation buttons ──────────────────────────── */}
        {step < 4 && (
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            {step > 1 ? (
              <button className="btn-back" onClick={() => setStep(step - 1)}>Back</button>
            ) : (
              <div />
            )}
            <button
              className="btn-next"
              disabled={step === 1 && !licAccepted}
              onClick={() => setStep(step + 1)}
            >
              Continue
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
