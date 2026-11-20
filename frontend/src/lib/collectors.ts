import { useEffect, useState } from "react";
import { collectorApi, type CollectorDiagnostics, type DedicatedCollector } from "../directoryApi";

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

/**
 * A release collector build is plain semver ("1.7.0"). A dev/test build carries build metadata or a
 * pre-release tag ("0.1.542+996181a") and ignores update offers, so it can never update itself.
 * The collector list API does not say whether self-update is possible, so this is derived from the
 * version string.
 */
export const isReleaseVersion = (v: string | null | undefined): boolean => !!v && /^v?\d+\.\d+\.\d+$/.test(v.trim());

/** True when `a` is an older release than `b` (both must be plain semver). */
export function olderThan(a: string, b: string): boolean {
  const n = (v: string) => v.replace(/^v/, "").split(".").map(Number);
  const [x, y] = [n(a), n(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i];
  return false;
}

/** A dev/test build: it ignores update offers, so it can't update itself. */
export function isTestBuild(c: Pick<DedicatedCollector, "version">): boolean {
  return !!c.version && !isReleaseVersion(c.version);
}

export const collectorHost = (c: Pick<DedicatedCollector, "dns_hostname" | "hostname" | "name">) => c.dns_hostname || c.hostname || c.name;

/** Download the pre-configured collector installer (MSI, x64) for an existing collector and save it. */
export async function downloadCollectorMsi(name: string): Promise<string> {
  const f = await collectorApi.downloadInstaller({ name: name.trim() || "collector", format: "msi", arch: "amd64", gmsa: "" });
  const url = URL.createObjectURL(f.blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = f.filename;
  a.click();
  URL.revokeObjectURL(url);
  return f.filename;
}
