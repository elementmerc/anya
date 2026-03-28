import type { AnalysisResult, KsdMatch, DotNetMetadata } from "@/types/analysis";

interface Props {
  result: AnalysisResult;
}

const CONFIDENCE_COLORS: Record<string, string> = {
  Critical: "var(--risk-critical)",
  High: "var(--risk-high)",
  Medium: "var(--risk-medium)",
  Low: "var(--risk-low)",
};

function similarityPercent(distance: number): string {
  return `${Math.max(0, (1 - distance / 200) * 100).toFixed(1)}%`;
}

function KsdMatchCard({ match }: { match: KsdMatch }) {
  const color = CONFIDENCE_COLORS[match.confidence] || "var(--text-muted)";
  const similarity = similarityPercent(match.distance);

  return (
    <div
      className="rounded-lg p-4 mb-4 border animate-in fade-in duration-500"
      style={{
        borderColor: color,
        borderWidth: 2,
        background: "var(--card-bg)",
      }}
    >
      <div className="flex items-center gap-3 mb-3">
        <span
          className="px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider"
          style={{ background: color, color: "#fff" }}
        >
          Known Malware
        </span>
        <span
          className="px-2 py-0.5 rounded text-xs font-medium"
          style={{ background: "var(--bg-secondary)", color: "var(--text-primary)" }}
        >
          {match.confidence} confidence
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-[var(--text-muted)] block text-xs uppercase tracking-wider mb-1">
            Family
          </span>
          <span className="font-semibold text-[var(--text-primary)] text-lg capitalize">
            {match.family}
          </span>
        </div>
        <div>
          <span className="text-[var(--text-muted)] block text-xs uppercase tracking-wider mb-1">
            Function
          </span>
          <span className="font-semibold text-[var(--text-primary)] text-lg">
            {match.function || "—"}
          </span>
        </div>
        <div>
          <span className="text-[var(--text-muted)] block text-xs uppercase tracking-wider mb-1">
            Similarity
          </span>
          <span className="font-mono text-[var(--text-primary)]">{similarity}</span>
          <span className="text-[var(--text-muted)] text-xs ml-1">(distance: {match.distance})</span>
        </div>
        <div>
          <span className="text-[var(--text-muted)] block text-xs uppercase tracking-wider mb-1">
            Reference
          </span>
          <span className="font-mono text-xs text-[var(--text-secondary)] break-all">
            {match.reference_sha256.slice(0, 32)}...
          </span>
        </div>
      </div>

      {match.tags && match.tags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {match.tags.map((tag, i) => (
            <span
              key={i}
              className="px-2 py-0.5 rounded text-xs"
              style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)" }}
            >
              {tag}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function DotNetSection({ metadata }: { metadata: DotNetMetadata }) {
  return (
    <div
      className="rounded-lg p-4 mb-4 border animate-in fade-in duration-500"
      style={{ borderColor: "var(--border)", background: "var(--card-bg)" }}
    >
      <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 uppercase tracking-wider">
        .NET Assembly Analysis
      </h3>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
        {metadata.known_obfuscator && (
          <div className="col-span-full">
            <span
              className="px-2 py-1 rounded text-xs font-bold"
              style={{ background: "var(--risk-high)", color: "#fff" }}
            >
              Obfuscator: {metadata.known_obfuscator}
            </span>
          </div>
        )}

        <div>
          <span className="text-[var(--text-muted)] text-xs block">Types</span>
          <span className="font-mono text-[var(--text-primary)]">{metadata.type_count}</span>
        </div>
        <div>
          <span className="text-[var(--text-muted)] text-xs block">Methods</span>
          <span className="font-mono text-[var(--text-primary)]">{metadata.method_count}</span>
        </div>
        <div>
          <span className="text-[var(--text-muted)] text-xs block">P/Invoke</span>
          <span className="font-mono text-[var(--text-primary)]">{metadata.pinvoke_count}</span>
          {metadata.pinvoke_suspicious && (
            <span className="ml-1 text-xs" style={{ color: "var(--risk-high)" }}>
              (suspicious)
            </span>
          )}
        </div>
        <div>
          <span className="text-[var(--text-muted)] text-xs block">Name obfuscation</span>
          <span className="font-mono text-[var(--text-primary)]">
            {(metadata.obfuscated_names_ratio * 100).toFixed(0)}%
          </span>
        </div>
        <div>
          <span className="text-[var(--text-muted)] text-xs block">Reflection</span>
          <span className="font-mono text-[var(--text-primary)]">
            {metadata.reflection_usage ? "Yes" : "No"}
          </span>
        </div>
        <div>
          <span className="text-[var(--text-muted)] text-xs block">Encrypted blob</span>
          <span className="font-mono text-[var(--text-primary)]">
            {metadata.high_entropy_blob ? "Yes" : "No"}
          </span>
        </div>
        {metadata.clr_version && (
          <div>
            <span className="text-[var(--text-muted)] text-xs block">CLR Version</span>
            <span className="font-mono text-[var(--text-primary)]">{metadata.clr_version}</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default function IdentityTab({ result }: Props) {
  const ksdMatch = result.ksd_match;
  const dotnetMeta = result.pe_analysis?.dotnet_metadata;
  const hasContent = ksdMatch || dotnetMeta;

  if (!hasContent) return null;

  return (
    <div className="space-y-4 animate-in fade-in duration-300">
      {ksdMatch && <KsdMatchCard match={ksdMatch} />}
      {dotnetMeta && <DotNetSection metadata={dotnetMeta} />}
    </div>
  );
}
