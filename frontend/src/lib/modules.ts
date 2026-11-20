import type { ModuleKey } from "../api";
import { useAuth } from "../auth/context";

/** Where a customer asks for a module that is not part of their subscription. */
export const CONTACT_URL = "https://sentrigis.com/#contact";

export const MODULE_KEYS: ModuleKey[] = ["cloud", "endpoints", "vulnerabilities", "assets", "external"];

export interface ModuleInfo {
  label: string;
  /** What the module is, in one sentence (the locked page and the platform console). */
  description: string;
  /** What stops when the platform owner switches it off (platform console confirmation). */
  stops: string;
}

export const MODULES: Record<ModuleKey, ModuleInfo> = {
  cloud: {
    label: "Cloud security",
    description: "Cloud security finds risky settings, internet exposure and attack paths in your Azure, AWS and Google Cloud accounts.",
    stops: "Cloud resources, Exposure, Cloud issues and Attack paths are locked, cloud connections and scans stop, and scheduled cloud scans are skipped.",
  },
  endpoints: {
    label: "Endpoints & servers",
    description: "Endpoints & servers keeps your Windows, Mac and Linux computers and servers updated and protected, and shows threats on them.",
    stops:
      "Computers & servers and Threats are locked, remote actions, scripts and remote support stop, and new agents cannot be added (unless Assets & identity is on).",
  },
  vulnerabilities: {
    label: "Vulnerabilities",
    description: "Vulnerabilities shows known security flaws in the software you run and what to fix first.",
    stops: "The Vulnerabilities page, its details and fix guidance are locked.",
  },
  assets: {
    label: "Assets & identity",
    description: "Assets & identity keeps your hardware register, directories (Active Directory, Entra ID, Google) and network devices in one place.",
    stops: "Hardware register and Network are locked, directory and network-scan settings stop, and scheduled directory syncs and network scans are skipped.",
  },
  external: {
    label: "Attack surface & pre-ASV",
    description:
      "Attack surface scans your internet-facing domains and addresses from outside and shows what an attacker can see. It produces a PCI practice report (not an official ASV scan report).",
    stops: "Attack surface, Internet-facing issues and Reports are locked and scheduled external scans stop. Targets, findings and reports are kept.",
  },
};

/** Which product modules the signed-in organisation has; the others are shown locked. */
export function useModules(): { has: (...keys: ModuleKey[]) => boolean } {
  const { organization } = useAuth();
  // Until the session is known (or against an older backend) nothing is locked.
  const on = organization?.modules ?? MODULE_KEYS;
  return { has: (...keys) => keys.some((k) => on.includes(k)) };
}
