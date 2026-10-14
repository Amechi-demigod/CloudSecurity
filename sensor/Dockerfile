# CNAPP runtime sensor
#   docker build -t cnapp/runtime-sensor:0.1.0 sensor/
#   docker build --build-arg WITH_EBPF=true -t cnapp/runtime-sensor:0.1.0-ebpf sensor/
#
# Debian bookworm ships Python 3.11 and the matching python3-bpfcc package,
# which keeps the optional eBPF build simple.
FROM debian:bookworm-slim

ARG WITH_EBPF=false
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && if [ "$WITH_EBPF" = "true" ]; then apt-get install -y --no-install-recommends python3-bpfcc bpfcc-tools; fi \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sensor
COPY runtime_sensor/ /opt/sensor/runtime_sensor/

ENV PYTHONPATH=/opt/sensor \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENSOR_PROC_ROOT=/host/proc \
    SENSOR_HOST_ROOT=/host \
    SENSOR_SYS_ROOT=/host/sys

# Runs as root *inside* the container because reading other users'
# /proc/<pid>/{exe,maps,fd} needs uid 0 + CAP_SYS_PTRACE. The DaemonSet drops
# every other capability and mounts host paths read-only.
ENTRYPOINT ["python3", "-m", "runtime_sensor"]
