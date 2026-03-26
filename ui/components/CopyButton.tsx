import { Copy, Check } from "lucide-react";
import { useState } from "react";
import { useToast } from "./Toast";

export default function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(text);
    setCopied(true);
    toast("Copied to clipboard", "success");
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      onClick={(e) => void handleCopy(e)}
      title={label || "Copy"}
      style={{
        background: "transparent",
        border: "none",
        cursor: "pointer",
        padding: 2,
        opacity: copied ? 1 : 0,
        transition: "opacity 150ms",
        color: copied ? "var(--risk-low)" : "var(--text-muted)",
        display: "flex",
        alignItems: "center",
        flexShrink: 0,
      }}
      className="copy-btn-hover"
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}
