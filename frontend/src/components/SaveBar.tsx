import { useUnsavedGuard } from "../lib/unsaved";
import { Button } from "./ui";

/** Sticky "N unsaved changes · Discard · Save changes" bar. Renders nothing when there are no changes. */
export function SaveBar({
  count,
  onSave,
  onDiscard,
  saving = false,
  note,
}: {
  count: number;
  onSave: () => void;
  onDiscard: () => void;
  saving?: boolean;
  /** Optional consequence text shown under the count. */
  note?: string;
}) {
  useUnsavedGuard(count > 0);
  if (count === 0) return null;
  return (
    <div role="region" aria-label="Unsaved changes" className="sticky bottom-0 z-20 mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-surface px-4 py-3 shadow-lg">
      <div className="text-sm">
        <div className="font-semibold text-ink">
          {count} unsaved {count === 1 ? "change" : "changes"}
        </div>
        {note && <div className="mt-0.5 text-xs text-ink-2">{note}</div>}
      </div>
      <div className="flex gap-2">
        <Button onClick={onDiscard} disabled={saving}>Discard</Button>
        <Button variant="primary" onClick={onSave} disabled={saving}>{saving ? "Saving…" : "Save changes"}</Button>
      </div>
    </div>
  );
}
