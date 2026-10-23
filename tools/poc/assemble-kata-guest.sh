#!/usr/bin/env bash
# Build only a NEW task-owned Kata rootfs. Never edit installed assets.
set -euo pipefail
SOURCE=${1:?original Kata image}
USERSPACE=${2:?assembled probe root}
DEST=${3:?new absolute destination image}
[[ "$DEST" = /* && ! -e "$DEST" ]] || exit 2
[[ -f "$SOURCE" && -d "$USERSPACE" ]] || exit 2
sfdisk --json "$SOURCE" | python3 -c '
import json,sys
table=json.load(sys.stdin)["partitiontable"]
parts=table["partitions"]
if not (table["label"]=="dos" and table.get("sectorsize",512)==512
        and len(parts)==1 and parts[0]["start"]==6144 and parts[0]["type"]=="83"):
    raise SystemExit("unsupported original Kata image geometry")
'
WORK="${DEST}.mount"
mkdir -m 700 "$WORK"
LOOP=''
cleanup() {
 if mountpoint -q "$WORK"; then umount "$WORK"; fi
 if [[ -n "$LOOP" ]]; then losetup -d "$LOOP"; fi
 if [[ -d "$WORK" ]]; then rmdir "$WORK"; fi
}
trap cleanup EXIT
cp --reflink=auto "$SOURCE" "$DEST"
truncate -s 1073741824 "$DEST"
# Preserve exact original partition start (6144 sectors), expand only this copy.
printf '6144,2091008,83\n' | sfdisk --no-reread --force -N 1 "$DEST"
LOOP=$(losetup --find --show --offset 3145728 --sizelimit 1070596096 "$DEST")
e2fsck -fy "$LOOP" || test "$?" = 1
resize2fs "$LOOP"
mount "$LOOP" "$WORK"
cp -a "$USERSPACE/usr/lib/python3.12" "$WORK/usr/lib/"
cp -a "$USERSPACE/usr/bin/python3.12" "$WORK/usr/bin/"
# Shared dependencies came from matching Ubuntu noble host; record all hashes.
for dir in lib/x86_64-linux-gnu usr/lib/x86_64-linux-gnu lib64; do
 if [[ -d "$USERSPACE/$dir" ]]; then mkdir -p "$WORK/$dir"; cp -a "$USERSPACE/$dir/." "$WORK/$dir/"; fi
done
cp "$USERSPACE/usr/sbin/bpftool" "$WORK/usr/sbin/bpftool"
mkdir -p "$WORK/opt/agentsuite-guardd" "$WORK/etc/agentsuite-guardd" "$WORK/etc/systemd/system/kata-containers.target.wants"
cp -a "$USERSPACE/guardd/agentsuite_guardd" "$WORK/opt/agentsuite-guardd/"
cp "$USERSPACE/network.bpf.o" "$WORK/opt/agentsuite-guardd/network.bpf.o"
cat > "$WORK/etc/agentsuite-guardd/guest.json" <<'EOF'
{"port":1030,"state":"/run/agentsuite-guardd/state.sqlite","pins":"/sys/fs/bpf/agentsuite-guardd","object":"/opt/agentsuite-guardd/network.bpf.o"}
EOF
chmod 600 "$WORK/etc/agentsuite-guardd/guest.json"
# Runtime-owned stable scope exists before identity discovery or Kata Create.
# Guardd remains an observer/enforcer of existing targets, never target creator.
cat > "$WORK/etc/systemd/system/runtime-execution-scope.service" <<'EOF'
[Unit]
Description=Runtime-owned prepared execution parent
Before=agentsuite-guardd-guest.service kata-agent.service
[Service]
Type=oneshot
ExecStart=/usr/bin/mkdir -p -m 0755 /sys/fs/cgroup/ateomchv
ExecStart=/usr/bin/chmod 0755 /sys/fs/cgroup/ateomchv
RemainAfterExit=yes
[Install]
WantedBy=kata-containers.target
EOF
ln -s ../runtime-execution-scope.service "$WORK/etc/systemd/system/kata-containers.target.wants/runtime-execution-scope.service"
cat > "$WORK/etc/systemd/system/agentsuite-guardd-guest.service" <<'EOF'
[Unit]
Description=Runtime-neutral guest execution enforcement
Requires=runtime-execution-scope.service
After=sys-fs-bpf.mount runtime-execution-scope.service
Before=kata-agent.service
[Service]
Type=notify
NotifyAccess=main
# Explicit bounded startup; see readiness candidate deadline assessment.
TimeoutStartSec=30s
RuntimeDirectory=agentsuite-guardd
# Ownership DB and WAL must survive explicit service stop/start while pins live.
RuntimeDirectoryPreserve=yes
RuntimeDirectoryMode=0700
Environment=PYTHONPATH=/opt/agentsuite-guardd
ExecStart=/usr/bin/python3.12 -c "from agentsuite_guardd.guest_stream import serve_file; serve_file('/etc/agentsuite-guardd/guest.json')"
Restart=on-failure
RestartSec=1
[Install]
WantedBy=kata-containers.target
EOF
ln -s ../agentsuite-guardd-guest.service "$WORK/etc/systemd/system/kata-containers.target.wants/agentsuite-guardd-guest.service"
find "$WORK/opt/agentsuite-guardd" -type f -exec sha256sum {} + > "${DEST}.files.sha256"
sync
# Finalize filesystem bytes before selecting the whole-image digest.
# Retain EXIT trap for earlier failures; cleanup is safe to call again.
cleanup
LOOP=''
trap - EXIT
sha256sum "$SOURCE" "$DEST"
