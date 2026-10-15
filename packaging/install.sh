#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "agentsuite-guardd install must run as root" >&2
  exit 1
fi
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python3 -m pip install --disable-pip-version-check "$ROOT"
command -v /usr/local/bin/agentsuite-guardd >/dev/null
install -d -m 0700 /etc/agentsuite-guardd /var/lib/agentsuite-guardd
install -d -m 0750 /run/agentsuite-guardd
install -m 0640 "$ROOT/config/config.json" /etc/agentsuite-guardd/config.json
if [ ! -e /etc/agentsuite-guardd/signing.seed ]; then
  umask 077
  python3 -c 'import secrets,sys;sys.stdout.buffer.write(secrets.token_bytes(32))' > /etc/agentsuite-guardd/signing.seed
fi
chown root:root /etc/agentsuite-guardd/signing.seed
chmod 0600 /etc/agentsuite-guardd/signing.seed
install -d -m 0755 /usr/local/share/agentsuite-guardd/gadget /usr/local/libexec
install -m 0644 "$ROOT/gadget/program.bpf.c" /usr/local/share/agentsuite-guardd/gadget/program.bpf.c
install -m 0755 "$ROOT/packaging/load-gadget.sh" /usr/local/libexec/agentsuite-guardd-load-gadget
install -m 0644 "$ROOT/packaging/agentsuite-guardd-gadget.service" /etc/systemd/system/agentsuite-guardd-gadget.service
install -m 0644 "$ROOT/packaging/agentsuite-guardd.service" /etc/systemd/system/agentsuite-guardd.service
systemctl daemon-reload 2>/dev/null || true
echo "Installed locally. Verify BPF LSM prerequisites, then enable both service units."
