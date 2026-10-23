# Setup and builds

## 1. Acquire exact source

Use the [checkout commands](README.md#get-the-source). Set these to your actual
absolute paths, keeping the documentation checkout separate:

```sh
export DOCS="$PWD/guardd-poc-docs"
export POC="$PWD/enforcement-poc"
export SRC="$POC/sources"
mkdir -p "$POC/evidence" "$POC/cache"
```

`sources.json` records all eight source identities, upstream bases and result
trees. It includes the unchanged Suite source. Do not replace pinned commits
with moving `main`, install unrelated released modules, or change module paths
to owner-fork URLs.

| Source directory | Public repository / branch |
|---|---|
| `guardd` | `vfalico/agentsuite-guardd`, `poc/whole-requirement-v1` |
| `orka` | `vfalico/orka-public`, `poc/whole-requirement-v1` |
| `sessions` | `vfalico/sessions-public`, `poc/whole-requirement-v1` |
| `kaimahi` | `vfalico/kaimahi-public`, `poc/whole-requirement-v1` |
| `kagent` | `vfalico/kagent-public`, `poc/whole-requirement-v1` |
| `substrate-kagent` | `vfalico/substrate-public`, `poc/whole-requirement-v1-kagent` |
| `substrate-sessions` | `vfalico/substrate-public`, `poc/whole-requirement-v1-sessions` |
| `suite` | `vfalico/suite-public`, `poc/whole-requirement-v1` |

The source module manifests retain explicit relative development replacements.
They resolve within this declared directory layout. External workspaces make
the companion selection explicit; no private registry, rewritten import,
`go work sync` or unexplained `go mod tidy` is needed. Never put both Substrate
modules into one Go workspace.

## 2. Host and toolchain

The recorded native environment was Linux/amd64, Go **1.27.2** and Python
**3.12**, with BPF-capable kernels and separately prepared VM/container assets.
Individual modules may declare older Go language versions; use the pinned
compiler for this reproduction.

Install Go from an authenticated official distribution; check `go version`.
Use ordinary OS packages for Python/venv, Git, C compiler, clang, libbpf1,
libbpf/libelf development headers, bpftool, make, OpenSSL and build tools.
VM tests additionally require KVM, Kata/Cloud Hypervisor, virtiofsd, Docker,
QEMU, cpio, gzip and filesystem/loop-device tools. Cluster tests require
kubectl, kind and appropriate envtest assets.

Do not run native experiments on a shared production host. Plan roughly
60 GiB of free space for source, module/build caches, kernel work and VM assets,
then measure actual allocations. Retain **more than 5 GiB and 1,024 free inodes**
after projected allocation on every affected root/Docker/output filesystem.
Source-only checkout has a smaller admission check. No script prunes existing
caches, images or tasks to manufacture headroom.

```sh
export GOTOOLCHAIN=local
export GOMODCACHE="$POC/cache/modules"
export GOCACHE="$POC/cache/go-build"
mkdir -p "$GOMODCACHE" "$GOCACHE"
```

Populate dependencies with normal checksum-verified module resolution using
the correct workspace. For offline builds set `GOPROXY=off`; missing cache
entries must fail visibly. A cache is not a shipped binary dependency.

```sh
python3.12 -m venv "$POC/venv"
"$POC/venv/bin/python" -m pip install -e "$SRC/guardd"
```

Guardd declares `cryptography>=46,<47` and its packaging dependencies in
`pyproject.toml`. Keep installation inside the venv, not system Python.
Record actual OS/Python package versions for a new run.

## 3. Build the companions

The included builder compiles test executables and ordinary binaries; it does
**not run the tests or qualify a native environment**:

```sh
python3 "$DOCS/tools/poc/build-native-companions.py" \
  --sources "$SRC" --out "$POC/build-01" \
  --manifest "$DOCS/docs/poc/sources.json" \
  --go "$(command -v go)" \
  --gomodcache "$GOMODCACHE" --gocache "$GOCACHE"
```

Use a new output directory on each attempt; failures retain their own logs.
The result includes commands, exact source trees, executable hashes and Go
build information. New binary hashes are not the identities of earlier runs.

Build Orka's ordinary manager and ACP exec helper separately:

```sh
make -C "$SRC/orka" ensure-ui-embed
GOWORK=off go -C "$SRC/orka" build -trimpath \
  -o "$POC/evidence/orka-manager" ./cmd
GOWORK=off go -C "$SRC/orka" build -trimpath \
  -o "$POC/evidence/orka-acp-exec-helper" ./cmd/orka-acp-exec-helper
GOWORK=off go -C "$SRC/orka" test -c \
  -o "$POC/evidence/orka-neutral-supervisor.test" ./workers/acp/supervisor
```

For runtime images and the exec helper use Orka's
`workers/acp/images/codex/Dockerfile` and its declared build inputs. Build from the locked
source; do not substitute a released controller or reuse a similarly named
old image. The `ensure-ui-embed` stub is for backend builds, not a UI release.
The source-pinned native tests and [fixture index](fixtures.json) show the
required executable paths and opt-in inputs.

## 4. Build a host BPF object

Run only after verifying `/sys/kernel/btf/vmlinux` exists and the kernel enables
BPF LSM/cgroup support:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c \
  > "$POC/evidence/vmlinux.h"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I"$POC/evidence" -I/usr/include \
  -c "$SRC/guardd/gadget/network.bpf.c" \
  -o "$POC/evidence/network.bpf.o"
```

Match the object to the kernel that will actually enforce. For a VM, host BPF
support is insufficient; build against the **guest** vmlinux BTF.

The neutral service is `serve-enforcement`, **not** the historical filesystem
provider's `serve` command or installer. Its operator-owned configuration is:

```json
{"socket":"/run/poc-enforcer/socket","state":"/var/lib/poc-enforcer/state.db","pins":"/sys/fs/bpf/poc-enforcer","object":"/absolute/qualified/network.bpf.o"}
```

Use dedicated root-owned directories and a root-owned regular config without
group/other write permissions. Root Unix peer credentials and exact transferred
handles are checked. Invoke explicitly on the disposable host:

```sh
sudo env PYTHONPATH="$SRC/guardd/src" "$POC/venv/bin/python" \
  -m agentsuite_guardd.cli --config /absolute/private/enforcer.json \
  serve-enforcement
```

That starts a real privileged service; source checkout/build does not.
Keep its owned process handle, state and restrictions until exact cleanup.

## 5. Guest and cluster lanes

Use each matching Substrate fork's `hack/microvm-assets/README.md` and pinned
asset recipes. The default stock guest did not satisfy the BPF-LSM/BTF boundary.
The observed custom guest used Linux **6.12.42**, source SHA-256
`4804528a29cd20309a0b41c30e5aeffc35fa21ee3358f4a706d4586d003bc1fb`,
with BPF syscall/JIT/LSM, BTF, cgroup, securityfs and tracing support.

The included guest build/assembly sources document the kernel configuration
delta, userspace/BPF assembly, new Kata image and runtime-owned pre-Create scope.
They require explicit original assets and a compatible userspace; they are not
an arbitrary-host installer. They must never install a host kernel or modify
installed Kata assets. The assembler supports only its stated image geometry.
Choose the built kernel/image/virtiofsd explicitly; record their hashes.

Orka's Pod lane requires a dedicated privileged-admission runtime namespace,
an installed Localhost seccomp profile allowing clone3, protected node-local
configuration/socket/state, the declared node labels and cgroup access.
Follow the source's `docs/development/node-local-execution-enforcement.md`.
Do not relabel general-purpose namespaces or fall back to Unconfined.

For kagent set the explicit immutable
`Harness.spec.substrate.snapshotPolicy.coldStartOnly: true` for the qualified
lane. Use the correct fork's guest control protocol with port 1030; the trusted
runtime bootstrap scope must exist before workload Create.

Generate disposable TLS keys/certificates and manager secrets **locally**.
Never copy production trust, publish kubeconfigs, bake keys into images, or
substitute plaintext remote control. Rendering a manifest, building an image
or obtaining readiness is not native qualification.
