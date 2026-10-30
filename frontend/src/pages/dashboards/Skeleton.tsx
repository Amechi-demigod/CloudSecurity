/** Placeholder cards while a dashboard tab loads. */
export function TabSkeleton({ tiles = 4 }: { tiles?: number }) {
  return (
    <div aria-busy="true" aria-live="polite">
      <span className="sr-only">Loading…</span>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: tiles }, (_, i) => (
          <div key={i} className="h-[118px] animate-pulse rounded-xl border border-line bg-surface-1" />
        ))}
      </div>
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="h-72 animate-pulse rounded-xl border border-line bg-surface-1 xl:col-span-2" />
        <div className="h-72 animate-pulse rounded-xl border border-line bg-surface-1" />
      </div>
    </div>
  );
}
