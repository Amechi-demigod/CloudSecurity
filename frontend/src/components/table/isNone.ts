/** Values a number column shows as a grey dash: nothing to count. */
export const isNone = (v: unknown): boolean => v === null || v === undefined || v === "" || v === 0 || v === "0" || v === "-" || v === "unknown";
