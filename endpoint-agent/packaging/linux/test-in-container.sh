#!/usr/bin/env bash
# CI test of the Linux packages inside a real distribution container (no systemd, no real server):
#   docker run --rm -e KIND=deb|rpm -v dist:/dist:ro -v packaging/linux:/pk:ro IMAGE bash /pk/test-in-container.sh
#
# Installs the freshly built package with the distribution's package manager, checks that the post-install handed a
# console-style enrolment file to the agent and deleted it, runs the REAL collectors (the distribution's own
# dpkg / rpm / apt / dnf / sshd / lsblk output) through `cnapp-agent inventory --print`, validates the report
# (check_inventory.py) and removes the package again. The service is not started (no systemd in a container).
set -euo pipefail

kind="${KIND:?KIND=deb or rpm}"

# An enrolment file like the one the console generates (a placeholder token: nothing here talks to a server).
mkdir -p /etc/cnapp-agent
cat > /etc/cnapp-agent/enroll.json <<'JSON'
{"version": 1, "server_url": "https://cnapp.example.invalid", "token": "cne_ci-placeholder-token-0000000000000000"}
JSON
chmod 0600 /etc/cnapp-agent/enroll.json

cd /dist
if [ "$kind" = deb ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 >/dev/null
  pkg="$(ls /dist/cnapp-agent_*_amd64.deb)"
  cp "$pkg" /tmp/cnapp-agent.deb
  apt-get install -y -qq /tmp/cnapp-agent.deb
else
  dnf install -y -q python3 >/dev/null
  pkg="$(ls /dist/cnapp-agent-*.x86_64.rpm)"
  cp "$pkg" /tmp/cnapp-agent.rpm
  dnf install -y -q /tmp/cnapp-agent.rpm
fi

test -x /usr/bin/cnapp-agent
test "$(stat -c %a /etc/cnapp-agent)" = 700
test "$(stat -c %a /var/lib/cnapp-agent)" = 700
test -f /usr/lib/systemd/system/cnapp-agent.service
# the post-install handed the enrolment file to the agent and deleted it
test ! -e /etc/cnapp-agent/enroll.json
/usr/bin/cnapp-agent status | tee /tmp/status.json
grep -q 'cnapp.example.invalid' /tmp/status.json
if grep -rq 'cne_ci-placeholder' /tmp/status.json; then echo "the token must never be printed" >&2; exit 1; fi
/usr/bin/cnapp-agent version

# Commands the Linux agent must not run are refused by the allowlist code (unit-tested); here: the real collectors.
/usr/bin/cnapp-agent inventory --print > /tmp/inventory.json
python3 /pk/check_inventory.py /tmp/inventory.json

# Removal cleans up: purge / erase deletes the device credential and logs.
if [ "$kind" = deb ]; then
  apt-get purge -y -qq cnapp-agent
else
  dnf remove -y -q cnapp-agent
fi
test ! -e /usr/bin/cnapp-agent
test ! -e /var/lib/cnapp-agent
# shellcheck source=/dev/null
. /etc/os-release
echo "OK: install, enrolment, real inventory and removal on $PRETTY_NAME"
