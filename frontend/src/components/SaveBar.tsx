import { createPortal } from "react-dom";
import { useSaveSlot } from "../lib/saveSlot";
import { useUnsavedGuard } from "../lib/unsaved";
import { Button } from "./ui";

/**
 * "● N unsaved changes · Discard · Save changes". Renders nothing when there are no changes.
 *
 * placement "header" (default): shows in the page title row (pinned at the top while the page scrolls) when the page
 * has a PageHeader, otherwise inline. placement "inline": always shows where it is placed, as a card. Use inline in
 * drawers/dialogs and whenever more than one SaveBar can be on screen at once.
 */
export function SaveBar({
  count,
  onSave,
  onDiscard,
  saving = false,
  note,
  placement = "header",
}: {
  count: number;
  onSave: () => void;
  onDiscard: () => void;
  saving?: boolean;
  /** Optional consequence text shown under the count. */
  note?: string;
  placement?: "header" | "inline";
}) {
  useUnsavedGuard(count > 0);
  const slot = useSaveSlot();
  if (count === 0) return null;
  const inHeader = placement === "header" && slot !== null;
  const bar = (
    <div
      role="region"
      aria-label="Unsaved changes"
      data-savebar=""
      data-print="hide"
      className={
        inHeader
          ? "flex flex-wrap items-center justify-end gap-x-3 gap-y-2"
          : "mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-surface-1 px-4 py-3"
      }
    >
      <div role="status" aria-live="polite" className="text-sm">
        <div className="font-semibold text-sev-medium">
          <span aria-hidden>● </span>
          {count} unsaved {count === 1 ? "change" : "changes"}
        </div>
        {note && <div className="mt-0.5 text-xs font-normal text-ink-2">{note}</div>}
      </div>
      <div className="flex gap-2">
        <Button onClick={onDiscard} disabled={saving}>Discard</Button>
        <Button variant="primary" onClick={onSave} disabled={saving}>{saving ? "Saving…" : "Save changes"}</Button>
      </div>
    </div>
  );
  return inHeader ? createPortal(bar, slot) : bar;
}
