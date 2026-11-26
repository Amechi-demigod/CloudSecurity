import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { MapPin } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { Card, Empty, ErrorNote, Stat } from "../../components/ui";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useUrlState } from "../../lib/useUrlState";
import { trackingApi, type Fleet, type FleetCity, type FleetDevice } from "../../trackingApi";
import RecentAlerts from "./RecentAlerts";

const BLUE = "#2563eb";
const ORANGE = "#f97316";

const cityKey = (c: { city: string | null; country_code: string | null }) => `${c.city ?? ""}|${c.country_code ?? ""}`;
const cityLabel = (c: { city: string | null; country: string | null }) => [c.city, c.country].filter(Boolean).join(", ") || "Unknown place";

/** One marker per city (the number of computers inside), auto-fitted to wherever the computers are. */
function CityMap({ cities, tileUrl, selected, onSelect }: {
  cities: FleetCity[]; tileUrl: string; selected: string | null; onSelect: (key: string) => void;
}) {
  const el = useRef<HTMLDivElement>(null);
  const map = useRef<L.Map | null>(null);
  const layer = useRef<L.LayerGroup | null>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  useEffect(() => {
    if (!el.current) return;
    const m = L.map(el.current, { zoomControl: true, attributionControl: true, scrollWheelZoom: false, worldCopyJump: true });
    L.tileLayer(tileUrl, {
      maxZoom: 18,
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors'
        + ' · IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a>',
    }).addTo(m);
    m.setView([20, 0], 2); // replaced by fitBounds as soon as there are markers
    layer.current = L.layerGroup().addTo(m);
    map.current = m;
    return () => {
      m.remove();
      map.current = null;
      layer.current = null;
    };
  }, [tileUrl]);

  useEffect(() => {
    const m = map.current;
    const g = layer.current;
    if (!m || !g) return;
    g.clearLayers();
    const points: L.LatLngTuple[] = [];
    for (const c of cities) {
      if (c.latitude == null || c.longitude == null) continue;
      const key = cityKey(c);
      const size = c.count >= 100 ? 44 : c.count >= 10 ? 38 : 32;
      const icon = L.divIcon({
        className: "",
        iconSize: [size, size],
        html: `<div style="width:${size}px;height:${size}px;border-radius:9999px;background:${c.flagged ? ORANGE : BLUE};color:#fff;`
          + `display:flex;align-items:center;justify-content:center;font:600 13px system-ui,sans-serif;`
          + `border:${key === selected ? "3px solid #111827" : "2px solid #fff"};box-shadow:0 1px 4px rgba(0,0,0,.4)">${c.count}</div>`,
      });
      const mk = L.marker([c.latitude, c.longitude], { icon, title: `${cityLabel(c)}: ${c.count}`, keyboard: true });
      mk.on("click", () => onSelectRef.current(key));
      mk.addTo(g);
      points.push([c.latitude, c.longitude]);
    }
    if (points.length === 1) m.setView(points[0], 8);
    else if (points.length > 1) m.fitBounds(L.latLngBounds(points), { padding: [40, 40], maxZoom: 10 });
  }, [cities, selected]);

  return <div ref={el} className="h-[28rem] w-full overflow-hidden rounded-lg border border-line" role="img" aria-label="Map of where computers are, one marker per city" />;
}

function DeviceRow({ d }: { d: FleetDevice }) {
  const where = d.network === "office" ? d.office : d.network === "away" ? `Away · ${d.city ?? d.country ?? "unknown"}` : d.network === "private" ? "Private network" : "No location yet";
  return (
    <li className="flex items-center justify-between gap-3 py-2 text-sm">
      <div className="min-w-0">
        <div className="truncate font-medium text-ink">
          {d.hostname}
          {d.outside_countries && <span className="ml-2 text-xs font-normal text-warn">Outside allowed countries</span>}
          {d.lost_mode && <span className="ml-2 text-xs font-normal text-sev-high">Lost mode</span>}
        </div>
        <div className="truncate text-xs text-ink-3">
          {where} · {d.last_seen_at ? fmtAgo(d.last_seen_at) : "never seen"}{d.not_seen ? " · not seen for a while" : ""}
        </div>
      </div>
      <Link to={`/devices/${d.id}`} className="shrink-0 text-sm font-medium text-accent hover:underline" aria-label={`Open ${d.hostname}`}>Open</Link>
    </li>
  );
}

function CityPanel({ fleet, cityKeyValue }: { fleet: Fleet; cityKeyValue: string | null }) {
  const city = fleet.cities.find((c) => cityKey(c) === cityKeyValue);
  if (!city) return <p className="text-sm text-ink-3">Select a city on the map to see its computers.</p>;
  const rows = fleet.devices.filter((d) => cityKey(d) === cityKeyValue && d.network !== "unlocated" && d.network !== "private");
  return (
    <div>
      <h3 className="mb-1 text-sm font-semibold text-ink">{cityLabel(city)} · {city.count} {city.count === 1 ? "computer" : "computers"}</h3>
      <ul className="divide-y divide-line">{rows.map((d) => <DeviceRow key={d.id} d={d} />)}</ul>
    </div>
  );
}

/** Computers & servers > Map view (?view=map). Analysts and admins get a map; viewers get the cities as a list. */
export default function FleetMap() {
  const { can } = useAuth();
  const [group, setGroup] = useUrlState("fgroup");
  const [status, setStatus] = useUrlState("fstatus");
  const [notSeen, setNotSeen] = useUrlState("fseen");
  const [picked, setPicked] = useState<string | null>(null);
  const { data, error, loading } = useApi(
    () => trackingApi.fleet({ group: group || undefined, status: status || undefined, notSeen: notSeen === "1" }),
    [group, status, notSeen],
    60000,
  );
  const cities = useMemo(() => data?.cities ?? [], [data]);
  const selected = picked && cities.some((c) => cityKey(c) === picked) ? picked : cities[0] ? cityKey(cities[0]) : null;

  if (!data) return error ? <ErrorNote error={error} /> : <p className="text-sm text-ink-3">{loading ? "Loading…" : ""}</p>;
  if (!data.enabled) {
    return (
      <Card>
        <Empty icon={MapPin} title="Device tracking is off"
          action={can("admin") ? <Link className="text-sm font-medium text-accent hover:underline" to="/admin/device-tracking">Open Settings, Device tracking</Link> : undefined}>
          Turn it on to see roughly where company laptops and desktops are, from their internet address (city level).
          {can("admin") ? "" : " Ask an administrator to turn it on."}
        </Empty>
      </Card>
    );
  }
  const t = data.tiles;
  const full = data.detail === "full";
  const chip = "rounded-full border px-3 py-1 text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent";
  return (
    <div>
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="At an office" value={t.at_office} sub="on an office network" />
        <Stat label="Away from offices" value={t.away} sub="anywhere else" />
        <Stat label="Outside allowed countries" value={t.outside_countries}
          sub={t.outside_countries > 0 ? "needs a look" : "none"} hint="Computers in a country that is not on the allowed list" />
        <Stat label="Missing" value={t.missing} sub="marked missing" />
      </div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {data.groups.length > 0 && (
          <select aria-label="Group" value={group} onChange={(e) => setGroup(e.target.value)}
            className="rounded border border-line bg-surface-2 px-2 py-1 text-xs text-ink">
            <option value="">All groups</option>
            {data.groups.map((g) => <option key={g} value={g}>{g}</option>)}
          </select>
        )}
        <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}
          className="rounded border border-line bg-surface-2 px-2 py-1 text-xs text-ink">
          <option value="">Any status</option>
          <option value="active">Online</option>
          <option value="stale">Stale</option>
          <option value="inactive">Inactive</option>
        </select>
        <button type="button" aria-pressed={notSeen === "1"} onClick={() => setNotSeen(notSeen === "1" ? "" : "1")}
          className={`${chip} ${notSeen === "1" ? "border-accent bg-accent/10 text-accent" : "border-line text-ink-2 hover:bg-surface-2"}`}>
          Not seen for {data.not_seen_days}+ days
        </button>
        {t.unlocated > 0 && <span className="text-xs text-ink-3">{t.unlocated} {t.unlocated === 1 ? "computer has" : "computers have"} no location yet</span>}
      </div>
      {cities.length === 0 ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card><Empty icon={MapPin} title="No computers to show">No computer matches these filters, or none has reported a location yet.</Empty></Card>
          <RecentAlerts />
        </div>
      ) : full ? (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <CityMap cities={cities} tileUrl={data.tile_url} selected={selected} onSelect={setPicked} />
            <p className="mt-2 text-xs text-ink-3">
              Orange: a computer there is outside the allowed countries or has not been seen for {data.not_seen_days}+ days.
              Locations are approximate (city level), from each computer&apos;s internet address.
            </p>
          </div>
          <div className="space-y-4">
            <RecentAlerts />
            <Card title="Computers"><CityPanel fleet={data} cityKeyValue={selected} /></Card>
          </div>
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Where computers are">
          <p className="mb-3 text-xs text-ink-3">The map is shown to analysts and administrators. Cities and countries only.</p>
          <ul className="space-y-4">
            {cities.map((c) => (
              <li key={cityKey(c)}><CityPanel fleet={data} cityKeyValue={cityKey(c)} /></li>
            ))}
          </ul>
        </Card>
        <RecentAlerts />
        </div>
      )}
      {data.truncated && <p className="mt-2 text-xs text-ink-3">Showing the first computers only; narrow the filters to see the rest.</p>}
    </div>
  );
}
