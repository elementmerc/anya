import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from "react";

interface ToastItem {
  id: number;
  message: string;
  type: "info" | "success" | "error";
}

interface ToastContextValue {
  toast: (message: string, type?: "info" | "success" | "error") => void;
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const idRef = useRef(0);

  const toast = useCallback((message: string, type: "info" | "success" | "error" = "info") => {
    const id = ++idRef.current;
    setToasts((prev) => [...prev.slice(-2), { id, message, type }]); // max 3
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }, []);

  const typeColors = {
    info: { bg: "var(--bg-elevated)", border: "var(--border)", color: "var(--text-primary)" },
    success: { bg: "var(--bg-elevated)", border: "var(--border)", color: "var(--text-primary)" },
    error: { bg: "rgba(239,68,68,0.1)", border: "rgba(239,68,68,0.3)", color: "#ef4444" },
  };

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div style={{
        position: "fixed", bottom: 16, right: 16, zIndex: 9999,
        display: "flex", flexDirection: "column", gap: 8, pointerEvents: "none",
      }}>
        {toasts.map((t) => {
          const c = typeColors[t.type];
          return (
            <div key={t.id} style={{
              padding: "10px 16px", borderRadius: "var(--radius)",
              background: c.bg, border: `1px solid ${c.border}`, color: c.color,
              fontSize: "var(--font-size-sm)", boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
              animation: "toast-slide-in 200ms ease-out",
              pointerEvents: "auto", maxWidth: 320,
            }}>
              {t.message}
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
