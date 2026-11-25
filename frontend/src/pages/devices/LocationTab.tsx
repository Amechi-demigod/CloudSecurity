import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { MapPin } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { Button, Card, Empty, Tag } from "../../components/ui";
import { fmtAgo } from "../../lib/format";
import { fmtInZone, trackingApi, type DeviceLocation, type LocationEvent } from "../../trackingApi";

const DEFAULT_RADIUS_KM = 25;

/** Header pill: "At {office}" or "Away from offices" (only while tracking is on and a location is known). */
export function LocationPill({ loc }: { loc: DeviceLocation | null }) {
  if (!loc || !loc.enabled || !loc.eligible || !loc.current) return null;
  const c = loc.current;
  if (c.network === "office") return <Tag tone="good">At {c.office}</Tag>;
  if (c.network === "private") return <Tag>On a private network</Tag>;
  return <Tag tone="warn">Away from offices</Tag>;
}

function placeLine(c: { city: string | null; region?: string | null; country: string | null }): string {
  return [c.city, c.region, c.country].filter(Boolean).join(", ") || "Unknown place";
}

/** A Leaflet map: the point and a dashed circle of the accuracy radius. Tile URL comes from the server. */
function AreaMap({ lat, lon, radiusKm, tileUrl }: { lat: number; lon: number; radiusKm: number; tileUrl: string }) {
  const el = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!el.current) return;
    const map = L.map(el.current, { zoomControl: true, attributionControl: true, scrollWheelZoom: false });
    L.tileLayer(tileUrl, {
      maxZoom: 18,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors',
    }).addTo(map);
    const circle = L.circle([lat, lon], {
      radius: radiusKm * 1000, color: "#2563eb", weight: 2, dashArray: "6 6", fillColor: "#2563eb", fillOpacity: 0.12,
    }).addTo(map);
    L.circleMarker([lat, lon], { radius: 6, color: "#fff", weight: 2, fillColor: "#2563eb", fillOpacity: 1 }).addTo(map);
    map.fitBounds(circle.getBounds(), { padding: [20, 20] });
    return () => {
      map.remove();
    };
  }, [lat, lon, radiusKm, tileUrl]);
  return (
    <div className="relative overflow-hidden rounded-lg border border-line">
      <div ref={el} className="h-72 w-full" role="img" aria-label="Map of the approximate area" />
      <div className="pointer-events-none absolute left-2 top-2 z-[500] rounded bg-surface/90 px-2 py-1 text-xs text-ink-2 shadow">
        Approximate area (city level), from the device&apos;s internet address
      </div>
    </div>
  );
}

function eventText(e: LocationEvent): string {
  if (e.kind === "arrived") return `Arrived at ${e.office}`;
  if (e.kind === "new_country") return `New country: ${e.country ?? "unknown"}${e.city ? ` (${e.city})` : ""}`;
  if (e.kind === "private") return "On a private network";
  return `Away from offices${e.city ? ` (${e.city})` : ""}`;
}

export function LocationTab({ deviceId, loc, error, reload, active }: {
  deviceId: string; loc: DeviceLocation | null; error: string | null; reload: () => void; active: boolean;
}) {
  const { can } = useAuth();
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  if (!loc) return error ? <div role="alert" className="text-sm text-sev-critical">{error}</div> : null;
  if (!loc.enabled) {
    return (
      <Card>
        <Empty icon={MapPin} title="Location tracking is off"
          action={can("admin") ? <Link className="text-sm font-medium text-accent hover:underline" to="/admin/device-tracking">Open tracking settings</Link> : undefined}>
          When it is on, company laptops report an approximate, city-level location taken from their internet address.
          {can("admin") ? "" : " Ask an administrator to turn it on."}
        </Empty>
      </Card>
    );
  }
  const c = loc.current;
  const full = loc.detail === "full";

  async function locate() {
    setBusy(true);
    setErr(null);
    setNote(null);
    try {
      await trackingApi.locateNow(deviceId);
      setNote("Asked the computer to report in. The location updates when it answers.");
      setTimeout(reload, 5000);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <Card
          title="Last known location"
          actions={can("analyst") && active ? <Button onClick={locate} disabled={busy}>{busy ? "Asking…" : "Locate now"}</Button> : undefined}
        >
          {!c ? (
            <p className="text-sm text-ink-3">No location yet. It appears after the computer next reports in.</p>
          ) : (
            <>
              <p className="mb-3 text-sm text-ink-2">
                {c.is_private ? "Private network" : c.available ? placeLine(c) : "Not available yet"} · seen {fmtAgo(c.last_seen_at)}
              </p>
              {full && c.latitude != null && c.longitude != null && !c.is_private ? (
                <AreaMap lat={c.latitude} lon={c.longitude} radiusKm={c.accuracy_km ?? DEFAULT_RADIUS_KM} tileUrl={loc.tile_url} />
              ) : (
                <p className="rounded border border-line bg-surface-2 px-3 py-6 text-center text-sm text-ink-3">
                  {c.is_private
                    ? "The computer is on a private network, so there is no map."
                    : full ? "Not available yet: the location database has not been downloaded." : "The map is shown to analysts and administrators."}
                </p>
              )}
            </>
          )}
          {note && <p role="status" className="mt-2 text-sm text-good">{note}</p>}
          {err && <p role="alert" className="mt-2 text-sm text-sev-critical">{err}</p>}
          <p className="mt-3 text-xs text-ink-3">
            Location is approximate. Phones and mobile networks often show the city where the carrier routes traffic.
            {" "}IP geolocation by <a className="text-accent hover:underline" href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a>.
          </p>
        </Card>
      </div>
      <div className="space-y-4">
        <Card title="Right now">
          {!c ? <p className="text-sm text-ink-3">Nothing yet.</p> : (
            <dl className="space-y-2 text-sm">
              <Row label="Network">
                {c.network === "office" ? `${c.office} (office network)` : c.network === "private" ? "Private network" : "Away from offices"}
              </Row>
              <Row label="City">{c.city ?? "—"}</Row>
              <Row label="Country">{c.country ?? "—"}</Row>
              {full && <Row label="Internet address"><span className="font-mono text-xs">{c.ip ?? "—"}</span></Row>}
              {full && <Row label="Internet provider">{c.provider ?? "—"}</Row>}
            </dl>
          )}
        </Card>
        <Card title="Location history">
          <p className="mb-2 text-xs text-ink-3">Last {loc.days} days · kept {loc.retention_days} days</p>
          {loc.history.length === 0 ? <p className="text-sm text-ink-3">No changes yet.</p> : (
            <ul className="space-y-2 text-sm">
              {loc.history.map((e) => (
                <li key={`${e.at}-${e.kind}`} className="flex justify-between gap-3">
                  <span>{eventText(e)}</span>
                  <span className="shrink-0 text-xs text-ink-3">{fmtInZone(e.at, loc.timezone)}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-2 text-xs text-ink-3">Times shown in {loc.timezone}.</p>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-ink-3">{label}</dt>
      <dd className="text-right text-ink">{children}</dd>
    </div>
  );
}
