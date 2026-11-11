#!/bin/sh
# Post-install of the cnapp-agent .deb / .rpm (POSIX sh; deb passes "configure", rpm a count: 1 install, 2 upgrade).
#
# Enrolment: put the enrolment file downloaded from the console (Devices > Enrollment > Linux servers) at
# /etc/cnapp-agent/enroll.json BEFORE installing the package. It carries the server address, an enrollment token
# and optionally a private CA. It is handed to `cnapp-agent configure --from-file`, which stores a protected
# pending enrollment, and then deleted: the token is never left behind in /etc. The token is never printed.
set -e

umask 077
CONF_DIR=/etc/cnapp-agent
ENROLL="$CONF_DIR/enroll.json"
BIN=/usr/bin/cnapp-agent

mkdir -p "$CONF_DIR" /var/lib/cnapp-agent /var/log/cnapp-agent
chmod 0700 "$CONF_DIR" /var/lib/cnapp-agent /var/log/cnapp-agent

if [ -f "$ENROLL" ]; then
  chmod 0600 "$ENROLL"
  if "$BIN" configure --from-file "$ENROLL" >/dev/null 2>&1; then
    rm -f "$ENROLL"
    echo "cnapp-agent: enrolment configuration stored; the service enrols on start."
  else
    # Keep the file so the admin can retry; say how, without echoing any of its content.
    echo "cnapp-agent: WARNING: $ENROLL could not be read by 'cnapp-agent configure --from-file'." >&2
    echo "cnapp-agent: the file is kept; fix it and run: sudo cnapp-agent configure --from-file $ENROLL" >&2
  fi
fi

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable cnapp-agent.service >/dev/null 2>&1 || true
  # Upgrade: restart into the new binary. Fresh install: start (it waits for enrolment if there is none yet).
  if [ "${1:-}" = "2" ] || [ -n "${2:-}" ]; then
    systemctl try-restart cnapp-agent.service >/dev/null 2>&1 || true
  else
    systemctl start cnapp-agent.service >/dev/null 2>&1 || true
  fi
else
  echo "cnapp-agent: systemd was not detected; run '/usr/bin/cnapp-agent run' under your own supervisor." >&2
fi
exit 0
