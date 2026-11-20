// Overview dashboard layout (backend app/api/dashboard_layout.py): one layout per organisation,
// read by everyone, saved by admins.
import { request } from "./api";

export interface OverviewLayout {
  /** Widget ids in display order (hidden ones keep their place). */
  order: string[];
  hidden: string[];
  /** 12 = full width, 6 = half width */
  widths: Record<string, 6 | 12>;
}

export interface OverviewLayoutResponse {
  layout: OverviewLayout | null;
  updated_at: string | null;
  updated_by: string | null;
}

export const overviewApi = {
  layout: () => request<OverviewLayoutResponse>("/api/dashboard/layout"),
  saveLayout: (layout: OverviewLayout) => request<OverviewLayoutResponse>("/api/dashboard/layout", { method: "PUT", body: JSON.stringify(layout) }),
};
