import type { ModuleKey } from "../api";
import { useAuth } from "../auth/context";

/** Where a customer asks for a module that is not part of their subscription. */
export const CONTACT_URL = "https://sentrigis.com/#contact";

export const MODULE_KEYS: ModuleKey[] = ["cloud", "endpoints", "vulnerabilities", "assets"];

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
    description: "Cloud security finds misconfigurations, internet exposure and attack paths across your Azure, AWS and Google Cloud accounts.",
    stops: "Inventory, Exposure, Posture findings and Attack paths are locked, cloud connectors and scans stop, and scheduled cloud scans are skipped.",
  },
  endpoints: {
    label: "Endpoints & servers",
    description: "Endpoints & servers manages your Windows, macOS and Linux devices: their health, remote actions and runtime threats.",
    stops:
      "Devices and Runtime threats are locked, remote actions, scripts and remote support stop, runtime sensors are refused and new agents cannot enrol (unless Assets & identity is on).",
  },
  vulnerabilities: {
    label: "Vulnerabilities",
    description: "Vulnerabilities matches the software on your devices and cloud workloads against known CVEs and shows what to fix first.",
    stops: "The Vulnerabilities page, vulnerability details and fix guidance are locked.",
  },
  assets: {
    label: "Assets & identity",
    description: "Assets & identity keeps your IT asset register, directories (Active Directory, Entra ID, Google) and network devices in one place.",
    stops: "IT assets and Network devices are locked, directory and network-scan settings stop, and scheduled directory syncs and network scans are skipped.",
  },
};

/** Which product modules the signed-in organisation has; the others are shown locked. */
export function useModules(): { has: (...keys: ModuleKey[]) => boolean } {
  const { organization } = useAuth();
  // Until the session is known (or against an older backend) nothing is locked.
  const on = organization?.modules ?? MODULE_KEYS;
  return { has: (...keys) => keys.some((k) => on.includes(k)) };
}
