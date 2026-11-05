/** Device classification labels (docs/DEVICE_MANAGEMENT.md#device-class). */
import type { DeviceClass } from "../api";

export const CLASS_LABEL: Record<DeviceClass, string> = {
  workstation: "Workstation",
  server: "Server",
  domain_controller: "Domain controller",
};

export const HYPERVISOR_LABEL: Record<string, string> = {
  vmware: "VMware",
  "hyper-v": "Hyper-V",
  kvm: "KVM / QEMU",
  xen: "Xen",
  virtualbox: "VirtualBox",
  parallels: "Parallels",
  nitro: "AWS Nitro",
  apple: "Apple Virtualization",
  other: "Other hypervisor",
};

export const CLOUD_LABEL: Record<string, string> = { azure: "Azure", aws: "AWS", gcp: "Google Cloud", oci: "Oracle Cloud" };

export const CLASS_FILTER_OPTIONS = [
  { value: "", label: "All" },
  { value: "workstation", label: "Workstations" },
  { value: "server", label: "Servers" },
  { value: "domain_controller", label: "Domain controllers" },
  { value: "unknown", label: "Unknown" },
];
