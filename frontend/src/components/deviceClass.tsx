import type { DeviceSummary } from "../api";
import { CLASS_LABEL, CLOUD_LABEL, HYPERVISOR_LABEL } from "../lib/deviceClass";
import { Tag } from "./ui";

type Classified = Pick<DeviceSummary, "device_class" | "class_source" | "is_virtual" | "hypervisor" | "cloud_provider">;

/** "Server" + "Virtual" tags; "inferred" classes say so in the tooltip. */
export function DeviceClassTag({ device, showVirtual = true }: { device: Classified; showVirtual?: boolean }) {
  const cls = device.device_class;
  const inferred = device.class_source === "inferred";
  const virtual = showVirtual && device.is_virtual;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {cls ? (
        <span title={inferred ? "Inferred from the OS name and model (agent older than 1.4.0)" : "Reported by the agent"}>
          <Tag tone={cls === "domain_controller" ? "critical" : cls === "server" ? "accent" : "default"}>
            {CLASS_LABEL[cls]}
            {inferred && <span className="text-ink-3"> (inferred)</span>}
          </Tag>
        </span>
      ) : (
        <span className="text-xs text-ink-3">—</span>
      )}
      {virtual && (
        <span title={[HYPERVISOR_LABEL[device.hypervisor ?? ""] ?? device.hypervisor, CLOUD_LABEL[device.cloud_provider ?? ""]].filter(Boolean).join(" · ") || "Virtual machine"}>
          <Tag>Virtual</Tag>
        </span>
      )}
    </span>
  );
}

/** Warning shown in confirmation dialogs of disruptive actions (suspend sign-in,
 *  lock, lost mode, wipe, remote session, scripts) when the target is a server
 *  or a domain controller. `action` reads "isolating it", "running a script on it".
 *  Approval policies are unchanged. */
export function ServerTargetWarning({ device, action }: { device: Pick<DeviceSummary, "device_class" | "hostname">; action: string }) {
  if (device.device_class === "domain_controller") {
    return (
      <div role="alert" className="rounded border border-sev-critical bg-sev-critical/15 px-3 py-2 text-sm">
        <strong className="text-sev-critical">This is a domain controller</strong> — {action} will affect the whole domain: sign-ins,
        group policy and every service that authenticates against it. Make sure another domain controller is available first.
      </div>
    );
  }
  if (device.device_class === "server") {
    return (
      <div role="alert" className="rounded border border-sev-high bg-sev-high/10 px-3 py-2 text-sm">
        <strong className="text-sev-high">This is a server</strong> — {action} can interrupt the services and users that depend on it.
      </div>
    );
  }
  return null;
}
