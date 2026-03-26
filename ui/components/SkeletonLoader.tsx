export default function SkeletonLoader({ width = "100%", height = 16, borderRadius = 4 }: {
  width?: string | number;
  height?: number;
  borderRadius?: number;
}) {
  return (
    <div style={{
      width, height, borderRadius,
      background: "var(--bg-surface)",
      animation: "batch-shimmer 1.5s ease-in-out infinite",
    }} />
  );
}

export function OverviewSkeleton() {
  return (
    <div style={{ padding: 24, display: "flex", gap: 24, maxWidth: 1200, margin: "0 auto" }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 16, width: 200 }}>
        <SkeletonLoader width={160} height={160} borderRadius={80} />
        <SkeletonLoader width={80} height={20} />
      </div>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 12 }}>
        <SkeletonLoader width="60%" height={20} />
        <SkeletonLoader width="100%" height={40} />
        <SkeletonLoader width="100%" height={40} />
        <SkeletonLoader width="100%" height={40} />
        <SkeletonLoader width="80%" height={40} />
        <SkeletonLoader width="100%" height={40} />
      </div>
    </div>
  );
}
