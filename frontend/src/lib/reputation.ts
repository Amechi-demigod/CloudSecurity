import type { RepDomain, RepFinding, RepGrade } from "../externalApi";

/** Plain-English wording and small calculations for the Reputation tab and domain page. */

export const GRADE_WORD: Record<RepGrade, string> = { A: "Excellent", B: "Good", C: "Fair", D: "Poor", F: "Failing" };
export const gradeTone = (g: RepGrade | null): "good" | "warn" | "bad" | "none" => (g === "A" || g === "B" ? "good" : g === "C" ? "warn" : g ? "bad" : "none");

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export const openFindings = (fs: RepFinding[], domain: string, cat?: string) => fs.filter((f) => f.status === "open" && f.domain === domain && (!cat || f.category === cat));
const has = (fs: RepFinding[], d: string, ...ids: string[]) => openFindings(fs, d).some((f) => ids.includes(f.check_id));

/** Things to fix = open findings that cost points (everything except informational). */
export const toFix = (d: RepDomain) => (d.counts.critical ?? 0) + (d.counts.high ?? 0) + (d.counts.medium ?? 0) + (d.counts.low ?? 0);

/** Email problems that let someone send mail that looks like it comes from the domain. */
export function emailFakeable(d: RepDomain, fs: RepFinding[]): string | null {
  const e = d.details?.email;
  if (!e) return null;
  if (!e.dmarc) return "no DMARC record";
  if (e.dmarc_policy === "none") return "DMARC set to none";
  if (!e.spf) return "no SPF record";
  if (has(fs, d.domain, "rep.spf_allow_all", "rep.spf_neutral", "rep.spf_multiple")) return "SPF is too loose";
  return null;
}

export function emailStatus(d: RepDomain, fs: RepFinding[]): string {
  const e = d.details?.email;
  if (!e) return "Not checked yet";
  const parts: string[] = [];
  if (!e.spf) parts.push("No SPF");
  else if (has(fs, d.domain, "rep.spf_allow_all", "rep.spf_neutral", "rep.spf_multiple")) parts.push("SPF too loose");
  if (!e.dmarc) parts.push("No DMARC");
  else if (e.dmarc_policy === "none") parts.push("DMARC set to none");
  if (parts.length) return parts.join(", ");
  const dkim = (e.dkim_selectors ?? []).length > 0;
  return dkim ? "SPF, DKIM and DMARC set" : "SPF and DMARC set, DKIM not found";
}

export const lookalikes = (d: RepDomain) => d.details?.lookalikes?.registered ?? [];
export function lookalikeStatus(d: RepDomain): string {
  const l = d.details?.lookalikes;
  if (!l) return "Not checked yet";
  if (l.note && l.registered.length === 0) return "Not checked for subdomains";
  const n = l.registered.length;
  if (n === 0) return "Nothing unusual";
  const mail = l.registered.filter((r) => r.mx.length > 0).length;
  return `${n} found, ${mail === 0 ? "none" : mail} with email`;
}

/** Certificates from an issuer not seen before for this domain. */
export function newCerts(d: RepDomain, fs: RepFinding[]) {
  const issuers = new Set(openFindings(fs, d.domain, "certificate").filter((f) => f.check_id === "rep.ct_new_issuer").map((f) => String(f.evidence?.issuer ?? f.title.replace("Certificate from a new issuer: ", ""))));
  return (d.details?.certificates?.recent ?? []).filter((c) => issuers.has(c.issuer));
}
export function certStatus(d: RepDomain, fs: RepFinding[]): string {
  const c = d.details?.certificates;
  if (!c || c.enabled === false) return c ? "Not switched on" : "Not checked yet";
  if (c.error) return "Could not be checked this time";
  const n = newCerts(d, fs).length;
  if (n > 0) return `${plural(n, "new certificate")} from a new issuer`;
  return "Nothing unusual";
}

/** True when this row's state is worth attention (used for the dot next to the status). */
export const sevPoints = (s: string) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[s] ?? 0;

export function runWords(status: string, message: string): string {
  if (status === "failed") return message || "The last check failed.";
  if (status === "partial") return message || "The last check was only partly done.";
  return "";
}
