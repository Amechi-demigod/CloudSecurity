import type { ScriptParam, ScriptParamValue } from "../api";

/** Short human description of a script parameter, e.g. "days: int 1–30 = 7". */
export function describeParam(p: ScriptParam): string {
  let t: string = p.type;
  if (p.type === "enum" && p.values) t = p.values.join(" | ");
  if (p.type === "int" && (p.min !== undefined || p.max !== undefined)) t += ` ${p.min ?? ""}–${p.max ?? ""}`;
  if (p.type === "string" && p.max_length) t += ` ≤${p.max_length}`;
  const opt = p.required === false ? "?" : "";
  const def = p.default !== undefined && p.default !== null && p.default !== "" ? ` = ${String(p.default)}` : "";
  return `${p.name}${opt}: ${t}${def}`;
}

/** Initial form values (strings for inputs, booleans for checkboxes) from the schema defaults. */
export function initialParamValues(params: ScriptParam[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (const p of params) {
    if (p.type === "bool") out[p.name] = p.default === true;
    else if (p.default !== undefined && p.default !== null) out[p.name] = String(p.default);
    else if (p.type === "enum" && p.required !== false && p.values?.length) out[p.name] = p.values[0];
    else out[p.name] = "";
  }
  return out;
}

/** Convert form values to typed parameters, returning an error message for the first invalid one. */
export function buildParams(
  params: ScriptParam[],
  values: Record<string, string | boolean>,
): { params: Record<string, ScriptParamValue>; error: string | null } {
  const out: Record<string, ScriptParamValue> = {};
  for (const p of params) {
    const v = values[p.name];
    if (p.type === "bool") {
      out[p.name] = v === true;
      continue;
    }
    const s = typeof v === "string" ? v.trim() : "";
    if (s === "") {
      if (p.required !== false) return { params: out, error: `${p.name} is required` };
      continue;
    }
    if (p.type === "int") {
      const n = Number(s);
      if (!Number.isInteger(n)) return { params: out, error: `${p.name} must be a whole number` };
      if (p.min !== undefined && n < p.min) return { params: out, error: `${p.name} must be at least ${p.min}` };
      if (p.max !== undefined && n > p.max) return { params: out, error: `${p.name} must be at most ${p.max}` };
      out[p.name] = n;
    } else if (p.type === "enum") {
      if (p.values && !p.values.includes(s)) return { params: out, error: `${p.name} must be one of ${p.values.join(", ")}` };
      out[p.name] = s;
    } else {
      if (p.max_length && s.length > p.max_length) return { params: out, error: `${p.name} is longer than ${p.max_length} characters` };
      if (p.pattern) {
        try {
          if (!new RegExp(`^(?:${p.pattern})$`).test(s)) return { params: out, error: `${p.name} does not match ${p.pattern}` };
        } catch {
          /* pattern not valid in JS: the server validates it */
        }
      }
      out[p.name] = s;
    }
  }
  return { params: out, error: null };
}
