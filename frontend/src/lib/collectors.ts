import { useEffect, useState } from "react";
import { collectorApi, type CollectorDiagnostics } from "../directoryApi";

/** Poll a collector until its diagnostics for command `commandId` are in. */
export function useDiagnostics(collectorId: string | null, commandId: string | null) {
  const [d, setD] = useState<CollectorDiagnostics | null>(null);
  useEffect(() => {
    if (!collectorId || !commandId) return;
    let stop = false;
    const tick = async () => {
      try {
        const c = await collectorApi.get(collectorId);
        const diag = c.diagnostics as CollectorDiagnostics;
        if (!stop && diag && diag.command_id === commandId) {
          setD(diag);
          if (diag.status !== "queued") return;
        }
      } catch {
        /* keep polling */
      }
      if (!stop) setTimeout(tick, 3000);
    };
    void tick();
    return () => {
      stop = true;
    };
  }, [collectorId, commandId]);
  return d;
}
