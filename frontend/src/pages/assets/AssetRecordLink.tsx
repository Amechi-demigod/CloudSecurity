import { Link } from "react-router-dom";
import { assetsApi } from "../../assetsApi";
import { AssetStatusBadge } from "../../components/assets";
import { useApi } from "../../lib/useApi";

/** Link from an agent device to its IT asset record (created automatically). */
export function AssetRecordLink({ deviceId }: { deviceId: string }) {
  const { data } = useApi(() => assetsApi.byDevice(deviceId), [deviceId]);
  if (!data) return null;
  return (
    <Link
      to={`/it-assets/${data.id}`}
      className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-2 py-0.5 text-xs text-ink hover:bg-line"
      title="IT asset record: owner, custody history, warranty, disposal"
    >
      Asset {data.asset_tag}
      <AssetStatusBadge status={data.status} />
    </Link>
  );
}
