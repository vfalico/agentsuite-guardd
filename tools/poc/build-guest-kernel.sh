#!/usr/bin/env bash
# Task-owned feasibility build; never installs a host kernel or changes boot configuration.
set -euo pipefail
ROOT=${1:?usage: build-guest-kernel.sh NEW_ABSOLUTE_WORKDIR KATA_BASE_CONFIG}
BASE_CONFIG=${2:?explicit Kata 6.12.42-162 base config required}
[[ "$BASE_CONFIG" = /* && -f "$BASE_CONFIG" ]] || exit 2
[[ "$ROOT" = /* && ! -e "$ROOT" ]] || { echo 'requires new absolute workspace' >&2; exit 2; }
mkdir -m 700 -p "$ROOT"
exec > >(tee "$ROOT/build.log") 2>&1
date -u --iso-8601=seconds
printf 'task-owned guest capability build; host=%s\n' "$(uname -r)"
for tool in gcc make flex bison pahole curl tar xz; do command -v "$tool"; done
curl --fail --location --max-time 300 --output "$ROOT/linux-6.12.42.tar.xz" https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.42.tar.xz
curl --fail --location --max-time 60 --output "$ROOT/sha256sums.asc" https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc
(cd "$ROOT"; grep -E '^[a-f0-9]{64}  linux-6\.12\.42\.tar\.xz$' sha256sums.asc > source.sha256; test -s source.sha256; sha256sum -c source.sha256)
(cd "$ROOT"; printf '%s  linux-6.12.42.tar.xz\n' '4804528a29cd20309a0b41c30e5aeffc35fa21ee3358f4a706d4586d003bc1fb' | sha256sum -c -)
# HTTPS plus published hash is recorded; no claim of OpenPGP signature verification.
tar -xJf "$ROOT/linux-6.12.42.tar.xz" -C "$ROOT"
cd "$ROOT/linux-6.12.42"
cp "$BASE_CONFIG" "$ROOT/original.config"
sha256sum "$ROOT/original.config"
cp "$ROOT/original.config" .config
scripts/config --enable BPF_SYSCALL --enable BPF_JIT --enable BPF_LSM --enable DEBUG_INFO_BTF --enable CGROUP_BPF --enable KPROBES --enable FTRACE --enable FUNCTION_TRACER --enable DYNAMIC_FTRACE --enable DYNAMIC_FTRACE_WITH_REGS --enable DYNAMIC_FTRACE_WITH_DIRECT_CALLS --enable KPROBE_EVENTS --enable BPF_EVENTS --enable SECURITYFS --enable SECURITY --enable SECURITY_NETWORK
scripts/config --set-str LOCALVERSION '-poc-guardd-feasibility' --disable LOCALVERSION_AUTO
make olddefconfig
for symbol in BPF_LSM BPF_EVENTS DEBUG_INFO_BTF SECURITYFS; do grep -qx "CONFIG_${symbol}=y" .config; done
cp .config "$ROOT/final.config"
diff -u "$ROOT/original.config" "$ROOT/final.config" > "$ROOT/config.diff" || test "$?" = 1
# Limit build pressure; no resource pools, services, host install, or boot changes.
make -j8 vmlinux bzImage
sha256sum vmlinux arch/x86/boot/bzImage .config > "$ROOT/artifacts.sha256"
cp vmlinux "$ROOT/vmlinux"
cp arch/x86/boot/bzImage "$ROOT/bzImage"
date -u --iso-8601=seconds
