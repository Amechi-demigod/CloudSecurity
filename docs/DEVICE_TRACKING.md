# Device tracking

Device tracking shows roughly where company laptops and desktops are, using the public internet address the
server sees when the device checks in. It is part of the **Endpoints & servers** module and is **off by default**
for every organisation.

## What it does

- Records, for each Windows and macOS laptop or desktop, where its internet address is (city level) and whether it
  is on one of your **office networks**.
- Shows a **Location** tab on the device page: last known location, an approximate map area, the current network,
  and a history of changes (arrived at an office, away from offices, new country).
- Linux machines, servers and domain controllers are **never** tracked.
- No agent change: the agent does not send any location. Nothing is read from the device's GPS, Wi-Fi or sensors.

## How it works

1. On every check-in and every command poll the server already stores the device's public address (`last_ip`,
   taken from the request with the trusted proxy settings, see `TRUST_PROXY_HEADERS`).
2. When tracking is on for the organisation and the device qualifies, the address is looked up in the DB-IP
   databases (city and ASN). Private, loopback, link-local, CGNAT (100.64.0.0/10) and documentation ranges are not
   looked up and show as "Private network".
3. The address is matched against the organisation's offices (single addresses or CIDR ranges).
4. A new history row is written only when the address, the office, the city or the country changes. Otherwise the
   latest row's `last_seen_at` moves forward.
5. Tracking never fails a check-in: any error is logged and ignored.

"Locate now" queues the existing `recheck_posture` command (reason "Locate now", analyst role), so the device
checks in at once and the location updates.

## Accuracy limits

- The location is **approximate and city level**. The map draws a dashed circle (about 25 km when the database
  gives no radius).
- Mobile carriers often route traffic through a hub city, so a phone-tethered laptop can appear in a different
  city or even region.
- VPNs and proxies show the location of the VPN exit, not the device.
- Addresses missing from the database show "Not available yet".

## Privacy

- Admins and analysts see the full location: map area, city, region, internet address and provider.
- Viewers see city and country only (and whether the device is at a named office): no address, coordinates, region
  or provider.
- Every change to tracking settings and offices is written to the audit log. Viewing a location is not audited.
- Tell staff that company laptops report their location while tracking is on. The settings page shows this notice.

## Retention

History is kept for 90 days (`DEVICE_LOCATION_RETENTION_DAYS`). Older rows are deleted when new locations are
written (at most once an hour per organisation). The device page shows the last 7 days by default
(`?days=` up to the retention).

## Time zones

Organisations have a tracking time zone (default UTC), and each office can have its own. Times in the console are
shown in the organisation's time zone.

## Settings (Settings > Device tracking, admins)

- **Tracking on**: the switch (saved with the Save bar).
- **Office networks**: name, internet addresses or ranges (up to 50, validated; ranges broader than /8 for IPv4 or
  /32 for IPv6 are refused), optional time zone. "Computers there now" counts devices whose latest location is
  that office and that checked in within two hours.
- **Allowed places**: countries where computers are expected (ISO 3166-1; empty = no rule).
- **Time zone**.

The alert settings (outside allowed countries, not seen for N days, after hours, hardware changed, agent stopped,
automatic lost mode outside countries) are stored but not used yet.

## IP geolocation data and licence

IP geolocation by [DB-IP](https://db-ip.com): the free "IP to City Lite" and "IP to ASN Lite" databases, licensed
**CC BY 4.0** (attribution required; it is shown on the settings page and next to the map). Files are read with the
`maxminddb` package.

| Setting | Default |
| --- | --- |
| `GEOIP_CITY_DB` | `backend/data/dbip-city-lite.mmdb` |
| `GEOIP_ASN_DB` | `backend/data/dbip-asn-lite.mmdb` |
| `GEOIP_AUTO_UPDATE` | `true` |

A leader-elected background job checks daily and downloads
`https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz` and `dbip-asn-lite-YYYY-MM.mmdb.gz` (current month,
falling back to the previous) when a file is missing or older than 30 days. Each download is opened to verify it and
swapped in atomically. Run it by hand with `python -m app.geoip.update`. For air-gapped installs set
`GEOIP_AUTO_UPDATE=false` and copy the files in. If a database is missing the console shows "Not available yet" and
nothing breaks.

## Map

Maps use OpenStreetMap tiles with Leaflet. `MAP_TILE_URL` (default
`https://tile.openstreetmap.org/{z}/{x}/{y}.png`) is returned to the console so it can be swapped later. The
frontend nginx Content-Security-Policy allows images from `tile.openstreetmap.org` only; if you change the tile
host, add it to `img-src` in `frontend/nginx/default.conf.template` and `deploy/onprem/nginx/onprem.conf.template`.
The attribution "© OpenStreetMap contributors" is always shown on the map. Note that opening a map sends the
viewer's browser to the tile host.

## API

Module-gated (Endpoints & servers) and scoped to the session's organisation.

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/device-tracking/settings` | analyst | Settings, retention, tile URL, whether the database is present |
| `PUT /api/device-tracking/settings` | admin | Partial update (audited as `device_tracking_settings_changed`) |
| `GET /api/device-tracking/countries` | any | ISO country list |
| `GET/POST /api/device-tracking/offices` | admin | List (with computers there now) / create |
| `PATCH/DELETE /api/device-tracking/offices/{id}` | admin | Edit / delete (audited) |
| `GET /api/devices/{id}/location?days=7` | viewer | Current location and history, role-filtered |
| `POST /api/devices/{id}/location/refresh` | analyst | "Locate now": queues `recheck_posture`, answers 202 |

## Data

`device_tracking_settings` (one row per organisation), `tracking_offices`, `device_locations` (indexed on
`device_id, last_seen_at`), and `devices.location_id` pointing at the newest row (cleared when that row is pruned).
