// Customize mode of the Overview: the widget list with on/off switches, the handle bar on every widget
// (drag, move up / down, width, hide) and the Save bar. Dragging is never the only way to move a widget.
import { ArrowDown, ArrowUp, EyeOff, GripVertical, Maximize2, Minimize2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { WIDGET_MAP, type Resolved, type WidgetDef } from "./widgets";

const focusRing = "focus:outline-none focus-visible:ring-2 focus-visible:ring-accent";
const btn = `inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-1 px-3 py-1.5 text-[12.5px] text-ink-2 transition hover:bg-surface-2 hover:text-ink disabled:cursor-not-allowed disabled:opacity-40 ${focusRing}`;

export function CustomizePanel({
  widgets,
  draft,
  onToggle,
  onReset,
  onClose,
}: {
  widgets: WidgetDef[];
  draft: Resolved;
  onToggle: (id: string) => void;
  onReset: () => void;
  onClose: () => void;
}) {
  return (
    <section aria-labelledby="ov-customize-title" className="mb-4 rounded-xl border border-accent/50 bg-surface-1 p-4 shadow-sm shadow-black/5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="ov-customize-title" className="text-sm font-semibold text-ink">
            Customize the Overview
          </h2>
          <p className="mt-0.5 text-xs text-ink-3">Choose what appears, then drag the boxes or use the arrows to arrange them. Saving changes the Overview for everyone in your organisation.</p>
        </div>
        <div className="flex gap-2">
          <button type="button" className={btn} onClick={onReset}>
            Reset to default
          </button>
          <button type="button" className={btn} onClick={onClose}>
            Close
          </button>
        </div>
      </div>
      <ul className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {widgets.map((w) => {
          const on = draft.on[w.id];
          return (
            <li key={w.id} className="flex items-center justify-between gap-3 rounded-lg border border-line px-3 py-2">
              <div className="min-w-0">
                <span id={`ov-sw-${w.id}`} className="block truncate text-[13px] font-semibold text-ink">
                  {w.title}
                </span>
                <span id={`ov-sw-d-${w.id}`} className="block truncate text-xs text-ink-3">
                  {w.description}
                </span>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={on}
                aria-labelledby={`ov-sw-${w.id}`}
                aria-describedby={`ov-sw-d-${w.id}`}
                onClick={() => onToggle(w.id)}
                className={`relative h-6 w-11 shrink-0 rounded-full border transition ${on ? "border-accent bg-accent" : "border-line bg-surface-2"} ${focusRing}`}
              >
                <span aria-hidden className={`absolute top-0.5 h-4.5 w-4.5 rounded-full bg-white shadow transition-all ${on ? "left-[22px]" : "left-0.5 bg-ink-3"}`} />
                <span className="sr-only">{on ? "On" : "Off"}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** A widget in edit mode: handle bar above the (inert, so not clickable) preview. */
export function EditFrame({
  id,
  index,
  count,
  width,
  dragging,
  onDragStart,
  onDragEnd,
  onDropOn,
  onMove,
  onWidth,
  onHide,
  children,
}: {
  id: string;
  index: number;
  count: number;
  width: 6 | 12;
  dragging: boolean;
  onDragStart: () => void;
  onDragEnd: () => void;
  onDropOn: () => void;
  onMove: (dir: -1 | 1) => void;
  onWidth: () => void;
  onHide: () => void;
  children: ReactNode;
}) {
  const [over, setOver] = useState(false);
  const title = WIDGET_MAP[id].title;
  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        onDropOn();
      }}
      className={`min-w-0 rounded-xl border-2 border-dashed ${over ? "border-accent bg-accent/5" : "border-line"} ${dragging ? "opacity-45" : ""}`}
    >
      <div className="flex flex-wrap items-center gap-1.5 border-b border-dashed border-line bg-surface-2 px-2 py-1.5 text-[12.5px]">
        <span
          draggable
          onDragStart={(e) => {
            try {
              e.dataTransfer.effectAllowed = "move";
              e.dataTransfer.setData("text/plain", id);
            } catch {
              /* some browsers refuse; the drag still works through state */
            }
            onDragStart();
          }}
          onDragEnd={onDragEnd}
          title="Drag to move"
          aria-hidden
          className="inline-flex cursor-grab items-center rounded p-1 text-ink-3 active:cursor-grabbing"
        >
          <GripVertical className="h-4 w-4" />
        </span>
        <span className="mr-auto min-w-0 truncate font-semibold text-ink">{title}</span>
        <button type="button" className={btn} disabled={index === 0} onClick={() => onMove(-1)} aria-label={`Move ${title} up`} title="Move up">
          <ArrowUp aria-hidden className="h-3.5 w-3.5" />
        </button>
        <button type="button" className={btn} disabled={index === count - 1} onClick={() => onMove(1)} aria-label={`Move ${title} down`} title="Move down">
          <ArrowDown aria-hidden className="h-3.5 w-3.5" />
        </button>
        <button type="button" className={`${btn} hidden lg:inline-flex`} onClick={onWidth}>
          {width === 12 ? <Minimize2 aria-hidden className="h-3.5 w-3.5" /> : <Maximize2 aria-hidden className="h-3.5 w-3.5" />}
          {width === 12 ? "Make half width" : "Make full width"}
          <span className="sr-only"> for {title}</span>
        </button>
        <button type="button" className={btn} onClick={onHide} aria-label={`Hide ${title}`}>
          <EyeOff aria-hidden className="h-3.5 w-3.5" />
          Hide
        </button>
      </div>
      <div inert className="select-none p-2">
        {children}
      </div>
    </div>
  );
}

export function SaveBar({ saving, error, onDiscard, onSave }: { saving: boolean; error: string | null; onDiscard: () => void; onSave: () => void }) {
  return (
    <div role="region" aria-label="Unsaved changes" className="sticky bottom-4 z-20 mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-accent bg-surface-1 px-4 py-3 shadow-lg shadow-black/20">
      <div className="min-w-0 text-[13px]">
        <b className="font-semibold text-ink">Unsaved changes</b>
        <span className="text-ink-2"> · The page below shows the result. Nothing changes for anyone until you save.</span>
        {error && (
          <span role="alert" className="mt-0.5 block text-ink">
            Could not save: {error}
          </span>
        )}
      </div>
      <div className="flex gap-2">
        <button type="button" className={btn} onClick={onDiscard} disabled={saving}>
          Discard
        </button>
        <button type="button" onClick={onSave} disabled={saving} className={`rounded-lg bg-accent px-3.5 py-1.5 text-[12.5px] font-semibold text-white transition hover:opacity-90 disabled:opacity-60 ${focusRing}`}>
          {saving ? "Saving…" : "Save changes"}
        </button>
      </div>
    </div>
  );
}
