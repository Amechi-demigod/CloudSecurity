import type { Vulnerability } from "../api";

export const SOURCE_LABEL: Record<string, string> = {
  nvd: "NVD (CPE)",
  osv: "OSV.dev",
  eol: "End of life (endoflife.date)",
  simulated: "Simulated",
};

export function cveUrl(v: Pick<Vulnerability, "cve_id" | "evidence">): string {
  const url = v.evidence && typeof v.evidence.url === "string" ? v.evidence.url : null;
  if (url && /^https:\/\/(nvd\.nist\.gov|osv\.dev|endoflife\.date)\//.test(url)) return url;
  return v.cve_id.startsWith("CVE-") ? `https://nvd.nist.gov/vuln/detail/${v.cve_id}` : `https://osv.dev/vulnerability/${v.cve_id}`;
}
