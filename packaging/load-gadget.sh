#!/bin/sh
set -eu
ROOT=${AGENTSUITE_GUARDD_BPFFS_ROOT:-/sys/fs/bpf/agentsuite-guardd}
SOURCE=${AGENTSUITE_GUARDD_GADGET_SOURCE:-/usr/local/share/agentsuite-guardd/gadget/program.bpf.c}
OBJECT=${AGENTSUITE_GUARDD_GADGET_OBJECT:-/var/lib/agentsuite-guardd/program.bpf.o}
BPFTOOL=${AGENTSUITE_GUARDD_BPFTOOL:-/usr/sbin/bpftool}
CLANG=${AGENTSUITE_GUARDD_CLANG:-/usr/bin/clang}
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) TARGET_ARCH=x86 ;;
  aarch64) TARGET_ARCH=arm64 ;;
  *) echo "unsupported BPF target architecture: $ARCH" >&2; exit 1 ;;
esac
[ -x "$BPFTOOL" ] || { echo "bpftool is required" >&2; exit 1; }
[ -x "$CLANG" ] || { echo "clang is required" >&2; exit 1; }
[ -r "$SOURCE" ] || { echo "Gadget source is missing: $SOURCE" >&2; exit 1; }
grep -qw bpf /sys/kernel/security/lsm || {
  echo "kernel BPF LSM is not enabled" >&2
  exit 1
}
mountpoint -q /sys/fs/bpf || { echo "bpffs is not mounted" >&2; exit 1; }
OBJECT_DIR=$(dirname "$OBJECT")
mkdir -p "$OBJECT_DIR" "$ROOT/maps" "$ROOT/links"
TMP=$(mktemp -d "$OBJECT_DIR/load.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM
LINKS="deny_writable_open deny_write deny_truncate deny_create deny_mkdir
deny_mknod deny_link deny_metadata deny_setxattr deny_removexattr deny_rename
deny_symlink deny_unlink deny_rmdir deny_mount_bypass"
verify_links() {
  directory=$1
  for link in $LINKS; do
    [ -e "$directory/$link" ] || return 1
    result=$("$BPFTOOL" -j link show pinned "$directory/$link" 2>/dev/null || true)
    echo "$result" | grep -q '"id"' || return 1
  done
}
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$TMP/vmlinux.h"
"$CLANG" -g -O2 -target bpf -D__TARGET_ARCH_${TARGET_ARCH} -I"$TMP" \
  -c "$SOURCE" -o "$TMP/program.bpf.o"
NEW_HASH=$(sha256sum "$TMP/program.bpf.o" | awk '{print $1}')
HASH_FILE="$OBJECT.sha256"
OLD_HASH=$(cat "$HASH_FILE" 2>/dev/null || true)
MAPS_READY=1
for name in guarded_targets guarded_paths filesystem_denials; do
  "$BPFTOOL" -j map show pinned "$ROOT/maps/$name" >/dev/null 2>&1 ||
    MAPS_READY=0
done
if [ "$MAPS_READY" -eq 1 ] && verify_links "$ROOT/links" &&
   [ "$OLD_HASH" = "$NEW_HASH" ]; then
  install -m 0600 "$TMP/program.bpf.o" "$OBJECT"
  exit 0
fi

if [ "$MAPS_READY" -eq 1 ]; then
  NEXT="$ROOT/links-next"
  mkdir -p "$NEXT"
  for link in $LINKS; do
    rm -f "$NEXT/$link"
  done
  "$BPFTOOL" prog loadall "$TMP/program.bpf.o" "$NEXT" autoattach \
    map name guarded_targets pinned "$ROOT/maps/guarded_targets" \
    map name guarded_paths pinned "$ROOT/maps/guarded_paths" \
    map name filesystem_denials pinned "$ROOT/maps/filesystem_denials"
  verify_links "$NEXT" || {
    echo "new BPF link set is incomplete" >&2
    exit 1
  }
  for link in $LINKS; do
    rm -f "$ROOT/links/$link"
    mv "$NEXT/$link" "$ROOT/links/$link"
  done
  rmdir "$NEXT"
else
  if [ -e "$ROOT/maps/guarded_targets" ]; then
    targets=$("$BPFTOOL" -j map dump pinned "$ROOT/maps/guarded_targets") || {
      echo "existing guarded-target map is unreadable" >&2
      exit 1
    }
    echo "$targets" | grep -q '"key"' && {
      echo "cannot replace incomplete BPF maps while guarded targets exist" >&2
      exit 1
    }
  fi
  for link in $LINKS; do
    rm -f "$ROOT/links/$link"
    if [ -d "$ROOT/links-next" ]; then
      rm -f "$ROOT/links-next/$link"
    fi
  done
  rmdir "$ROOT/links-next" 2>/dev/null || true
  rm -f "$ROOT/maps/guarded_targets" "$ROOT/maps/guarded_paths" \
    "$ROOT/maps/filesystem_denials"
  "$BPFTOOL" prog loadall "$TMP/program.bpf.o" "$ROOT/links" \
    autoattach pinmaps "$ROOT/maps"
fi

verify_links "$ROOT/links" || {
  echo "installed BPF link set is incomplete" >&2
  exit 1
}
for name in guarded_targets guarded_paths filesystem_denials; do
  "$BPFTOOL" -j map show pinned "$ROOT/maps/$name" >/dev/null
done
install -m 0600 "$TMP/program.bpf.o" "$OBJECT"
printf '%s\n' "$NEW_HASH" > "$TMP/program.sha256"
install -m 0600 "$TMP/program.sha256" "$HASH_FILE"
