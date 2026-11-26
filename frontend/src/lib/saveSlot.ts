import { useSyncExternalStore } from "react";

/** The element in the current PageHeader where SaveBar renders its content (null when no header is mounted). */
let slot: HTMLElement | null = null;
const listeners = new Set<() => void>();

export function registerSaveSlot(el: HTMLElement): () => void {
  slot = el;
  listeners.forEach((l) => l());
  return () => {
    if (slot === el) {
      slot = null;
      listeners.forEach((l) => l());
    }
  };
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}

export function useSaveSlot(): HTMLElement | null {
  return useSyncExternalStore(subscribe, () => slot, () => null);
}
