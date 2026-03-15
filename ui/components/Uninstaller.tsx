import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { X } from "lucide-react";
import "./Installer.css";

interface UninstallInfo {
  config_dir: string;
  data_dir: string;
  db_size_mb: number;
}

export function Uninstaller() {
  const [step, setStep] = useState(1);
  const [removeDatabase, setRemoveDatabase] = useState(true);
  const [removeConfig, setRemoveConfig] = useState(false);
  const [dbSizeMb, setDbSizeMb] = useState(0);
  const [progPct, setProgPct] = useState(0);
  const [progMsg, setProgMsg] = useState("");

  // Default to dark — SQLite may not be accessible during uninstall
  const dark = true;

  useEffect(() => {
    invoke<UninstallInfo>("get_uninstall_info")
      .then((info) => setDbSizeMb(info.db_size_mb))
      .catch(() => {});
  }, []);

  // Step 3: perform uninstall + progress animation
  useEffect(() => {
    if (step !== 3) return;
    const timers: ReturnType<typeof setTimeout>[] = [];

    const uninstallPromise = invoke("perform_uninstall", {
      removeDatabase,
      removeConfig,
    }).catch(console.error);

    const stages = [
      { pct: 20, msg: "Removing application files\u2026", delay: 700 },
      { pct: 45, msg: "Deleting analysis database\u2026", delay: 1200 },
      { pct: 65, msg: "Clearing preferences\u2026", delay: 800 },
      { pct: 82, msg: "Cleaning up\u2026", delay: 600 },
      { pct: 100, msg: "Done.", delay: 500 },
    ];

    let total = 0;
    for (const s of stages) {
      total += s.delay;
      timers.push(
        setTimeout(() => {
          setProgPct(s.pct);
          setProgMsg(s.msg);
        }, total)
      );
    }

    timers.push(
      setTimeout(async () => {
        await uninstallPromise;
        setStep(4);
      }, total + 400)
    );

    return () => timers.forEach(clearTimeout);
  }, [step, removeDatabase, removeConfig]);

  function handleClose() {
    getCurrentWindow().close();
  }

  const removedItems: string[] = ["Anya application"];
  if (removeDatabase) removedItems.push("Analysis database");
  if (removeConfig) removedItems.push("Preferences and config");

  return (
    <div className={`installer ${dark ? "dark" : "light"}`}>
      {/* Logo */}
      <svg width="48" height="44" viewBox="0 0 200 180" xmlns="http://www.w3.org/2000/svg" style={{ marginBottom: 6 }}>
        <line x1="36" y1="158" x2="100" y2="22" stroke="#e8e5dc" strokeWidth="14" strokeLinecap="round" />
        <line x1="164" y1="158" x2="100" y2="22" stroke="#e8e5dc" strokeWidth="14" strokeLinecap="round" />
        <line x1="58" y1="96" x2="142" y2="96" stroke="#D85A30" strokeWidth="12" strokeLinecap="round" />
      </svg>
      <span className="inst-title" style={{ fontSize: 15, fontWeight: 600, letterSpacing: "0.18em", marginBottom: 2 }}>ANYA</span>
      <span className="inst-sub" style={{ fontSize: 11, marginBottom: 20 }}>Uninstaller</span>

      <div className="installer-card">
        {/* Step dots */}
        {step < 4 && (
          <div style={{ display: "flex", gap: 6, justifyContent: "center", marginBottom: 16 }}>
            {[1, 2, 3, 4].map((s) => (
              <div key={s} className={`dot${s < step ? " done" : ""}${s === step ? " active" : ""}`} />
            ))}
          </div>
        )}

        {/* ── Step 1: What to remove ──────────────────────── */}
        {step === 1 && (
          <div className="inst-panel">
            <h3 className="card-head" style={{ margin: "0 0 8px", fontSize: 14, fontWeight: 600 }}>Choose what to remove</h3>
            <p className="card-body" style={{ margin: "0 0 14px", fontSize: 12, lineHeight: 1.6 }}>
              Select which data to delete along with the application.
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {/* App files — always checked, disabled */}
              <label className="check-row disabled" style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "8px 12px", borderRadius: 8, cursor: "default" }}>
                <input type="checkbox" className="done-opt-check" checked readOnly disabled style={{ marginTop: 2 }} />
                <div>
                  <span className="tog-lbl" style={{ fontSize: 12, fontWeight: 500 }}>Application files</span>
                  <p className="card-body" style={{ margin: "2px 0 0", fontSize: 11 }}>The Anya binary and all bundled assets</p>
                </div>
              </label>

              {/* Database */}
              <label style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "8px 12px", borderRadius: 8, cursor: "pointer" }} onClick={() => setRemoveDatabase(!removeDatabase)}>
                <input type="checkbox" className="done-opt-check" checked={removeDatabase} readOnly style={{ marginTop: 2 }} />
                <div>
                  <span className="tog-lbl" style={{ fontSize: 12, fontWeight: 500 }}>Analysis database</span>
                  <p className="card-body" style={{ margin: "2px 0 0", fontSize: 11 }}>
                    Your analysis history and cached results{dbSizeMb > 0 ? ` (${dbSizeMb} MB)` : ""}
                  </p>
                </div>
              </label>

              {/* Config */}
              <label style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "8px 12px", borderRadius: 8, cursor: "pointer" }} onClick={() => setRemoveConfig(!removeConfig)}>
                <input type="checkbox" className="done-opt-check" checked={removeConfig} readOnly style={{ marginTop: 2 }} />
                <div>
                  <span className="tog-lbl" style={{ fontSize: 12, fontWeight: 500 }}>Preferences and config</span>
                  <p className="card-body" style={{ margin: "2px 0 0", fontSize: 11 }}>Leave unchecked to keep settings if you reinstall later</p>
                </div>
              </label>
            </div>

            <p className="inst-hint" style={{ fontSize: 10, marginTop: "auto", paddingTop: 12 }}>
              Application files are always removed.
            </p>
          </div>
        )}

        {/* ── Step 2: Confirmation ────────────────────────── */}
        {step === 2 && (
          <div className="inst-panel danger">
            <h3 className="card-head" style={{ margin: "0 0 8px", fontSize: 14, fontWeight: 600 }}>This cannot be undone</h3>
            <p className="card-body" style={{ margin: "0 0 12px", fontSize: 12, lineHeight: 1.6 }}>
              The following will be permanently deleted:
            </p>

            <ul style={{ margin: "0 0 12px", paddingLeft: 20 }}>
              {removedItems.map((item) => (
                <li key={item} className="card-body" style={{ fontSize: 12, lineHeight: 1.8 }}>{item}</li>
              ))}
            </ul>

            <div className="warn-box">
              <span className="warn-icon">{"\u26A0"}</span>
              <span className="warn-text">
                Deleted data cannot be recovered. If you have important analysis results, export them before continuing.
              </span>
            </div>

            <p className="inst-hint" style={{ fontSize: 10, marginTop: "auto", paddingTop: 12 }}>
              This is permanent.
            </p>
          </div>
        )}

        {/* ── Step 3: Removing ────────────────────────────── */}
        {step === 3 && (
          <div className="inst-panel" style={{ justifyContent: "center" }}>
            <h3 className="card-head" style={{ margin: "0 0 8px", fontSize: 14, fontWeight: 600 }}>Uninstalling Anya</h3>
            <p className="card-body" style={{ margin: "0 0 20px", fontSize: 12, lineHeight: 1.6 }}>
              Removing selected files and cleaning up.
            </p>
            <div className="prog-track">
              <div className="prog-fill-red" style={{ width: `${progPct}%` }} />
            </div>
            <span className="prog-lbl">{progMsg}</span>
          </div>
        )}

        {/* ── Step 4: Done ────────────────────────────────── */}
        {step === 4 && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1 }}>
            <div className="done-icon-removed">
              <X size={20} style={{ color: "var(--text-muted)" }} />
            </div>
            <h3 className="done-title" style={{ margin: "0 0 4px", fontSize: 16, fontWeight: 600 }}>Anya has been removed</h3>
            <p className="done-sub" style={{ margin: "0 0 24px", fontSize: 12 }}>
              Thanks for using Anya. You can reinstall any time from themalwarefiles.com
            </p>
            <button
              onClick={handleClose}
              className="btn-back"
              style={{ padding: "10px 28px", fontSize: 13 }}
            >
              Close
            </button>
          </div>
        )}

        {/* ── Navigation buttons ──────────────────────────── */}
        {step === 1 && (
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button className="btn-next" onClick={() => setStep(2)}>Continue</button>
          </div>
        )}
        {step === 2 && (
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <button className="btn-back" onClick={() => setStep(1)}>Back</button>
            <button
              onClick={() => setStep(3)}
              style={{
                background: "#E24B4A", border: "none", color: "#fff", borderRadius: 6,
                padding: "8px 18px", fontSize: 12, fontWeight: 500, cursor: "pointer",
                fontFamily: "inherit", transition: "opacity 0.15s",
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.opacity = "0.85"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.opacity = "1"; }}
            >
              Yes, uninstall
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
