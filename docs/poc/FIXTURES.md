# Native fixture recipes

These are explicit development recipes, not an arbitrary-host installer or
fresh native acceptance. Use [setup](SETUP.md) first. The source lock includes
the complete runtime implementations; no original trace or private workstation
is needed to inspect/build them.

## Guest userspace and Kata image

Supply the pinned Kata base config and original image from the matching
Substrate asset recipe. The helpers build **new outputs only**:

```sh
bash "$DOCS/tools/poc/build-guest-kernel.sh" \
  "$POC/guest-kernel-01" /absolute/kata/config-6.12.42-162
python3 "$DOCS/tools/poc/assemble-guest-userspace.py" \
  --kernel-work "$POC/guest-kernel-01" \
  --guardd-source "$SRC/guardd" \
  --bpftool /absolute/compatible/bpftool \
  --probe "$DOCS/examples/poc/guest-capabilities.py" \
  --out "$POC/guest-userspace-01"
sudo bash "$DOCS/tools/poc/assemble-kata-guest.sh" \
  /absolute/pinned/original-kata.img "$POC/guest-userspace-01/root" \
  "$POC/guest-runtime-01.img"
```

The userspace recipe expects compatible Ubuntu noble x86-64 libraries and
Python 3.12 at the stated system paths. Use the actual compatible bpftool ELF,
not a distribution shell wrapper. It compiles BPF using the guest vmlinux BTF.
The final image includes the selected Guardd source/object, a guest service on
port 1030 and the trusted runtime-owned cgroup bootstrap before Kata Create.
The supported original partition is DOS, one Linux partition, 512-byte sectors,
start 6144. Other geometry refuses before copy/resize.

`guest-capabilities.py` is only a readable capability check. Its success does
not prove BPF attachment or native policy. The kernel build never installs a
host kernel; the image assembly never edits the original installed image.
Rebuilt kernel/image hashes need new run provenance.

## Orka model-free running allow/empty pair

The public fixture includes:

- `examples/poc/orka/workspace/`: minimal Suite source;
- useful and empty complete requirement envelopes;
- ordinary manager flag template, seed resources and namespace examples;
- containerd-derived held seccomp fixture plus its generator source;
- deterministic external inference/receiver fixture;
- a tiny TEST-only Node entrypoint probe;
- an OCI layer assembler and a parameterized public API runner.

The probe is a real post-release syscall, not fabricated model output.
It deliberately does not certify inference quality. The standard runtime
supervisor/helper/gate/adapter bytes remain those of your built parent image.
The OCI layer modifies only the explicit test entrypoint wrapper/probe.

### Prepare a disposable cluster

1. Create a new isolated kind cluster and private kubeconfig. Record its context,
   node/container name, node InternalIP, host gateway and API endpoint.
2. Apply the locked Orka CRDs using its normal manifests. Apply the example
   task/runtime namespaces, substituting your names consistently. Never reuse
   an unrelated namespace or controller.
3. Install `held-seccomp.json` into that node's kubelet seccomp directory as
   `poc/held.json`; it preserves the captured containerd default while permitting
   clone3. It is a **test fixture**, not a universal production profile.
4. Create a protected root-owned node directory, for example
   `/run/poc-normal-enforcer`, and install `enforcer-config.json` as `config.json`
   mode 0600. Label the node `example.org/poc-enforcer=v1`.
5. Build the normal Codex runtime from
   `workers/acp/images/codex/Dockerfile`, import it locally, and inspect its
   **platform manifest digest**. The assembler requires the manifest with
   `config`/`layers`, not an OCI index or a tag.
6. Build/import the test image with the assembler below. Load a separate locally
   digest-pinned BusyBox relay image into the node and replace the seed template's
   explicit placeholder. Do not use a floating image or pretend the example
   image digest is available from a registry.
7. Generate new local manager snapshot key, provider token and TLS key/cert
   according to the locked manager's accepted formats. Retain them only in the
   configured private manager-state directory.
8. Apply `seed-bootstrap.json` for the seed ServiceAccount/Role/RoleBinding/Agent
   and Service. The final
   Pod in `seed.json` is a **runner template**: do not apply that Pod yourself.
   The runner supplies its bounded command, exact addresses and unique identity.
   Keep the Agent name `sample` and the expected scoped service names, or adjust
   the fixture deliberately and record the difference.

For a new disposable manager-state directory, generate a fresh 32-byte snapshot
key (`openssl rand -out snapshot-key 32`), a fresh provider token and locally
trusted test TLS material. The locked manager accepts the snapshot key as raw
32 bytes or base64 text. Store `tls.crt`/`tls.key` under its configured `tls/`;
keep the directory mode 0700 and secret files mode 0600.

The node observer resolves protected state through `/proc/<nodepid>/root`;
do not lose that prefix or confuse node-visible and host-visible paths.
The task namespace needs `orka.ai/controller-mode=harness-v2`; the dedicated
runtime namespace needs privileged Pod admission. All cluster operations and
Kaimahi calls must use the configured context.

### Assemble the test image

```sh
python3 "$DOCS/tools/poc/assemble-orka-probe-image.py" \
  --node "$OWNED_KIND_NODE" --base "$EXACT_PARENT_PLATFORM_DIGEST" \
  --probe "$DOCS/examples/poc/orka/orka-entrypoint-probe.js" \
  --out "$POC/orka-probe-image-01"
```

The new directory contains `image.tar` and a build `receipt.json`. Import the
archive with the node's ordinary containerd mechanism and use the actual emitted
manifest digest as the configured image. It is a local build, not a publication.
The receipt verifies image construction; it is not runtime acceptance.

### Configure and run

Copy `config.example.json` to a private file. Replace **every** placeholder:
absolute tools/source/manifest/fixture/workspace/output paths; separate
task/runtime namespaces; exact context/node/IP/gateway/API; protected node
enforcer directory; private manager state; actual image/build receipt; and
the selected useful/empty envelope. The runner's `fixture_inputs` points to
the example Orka directory. Its `manifest` is the public `sources.json`.
Use a new private output under an owned mode-0700 parent.

Fill `expected_sha256` from the actual declared local inputs. This includes
the runner, fixture, tools, source lock, binaries, BPF object, envelope and
image build receipt. Hashes are integrity checks, not a claim that a different
binary/image has already passed native qualification. Set the manager template's
allowed controller username to the actual disposable cluster identity.

```sh
python3 "$DOCS/tools/poc/run-orka-running-empty.py" \
  --config /absolute/private/allow-config.json --check-inputs
sudo python3 "$DOCS/tools/poc/run-orka-running-empty.py" \
  --config /absolute/private/allow-config.json
```

`--check-inputs` validates local inputs/configuration only. Actual execution
additionally checks source trees, protected state, cluster/node identity,
namespaces, resources, image blobs and private prerequisites before launch.
It starts the ordinary manager and submits through ordinary `kmx run`; it does
not mutate Task status or invoke a private workload launcher.

Run empty with a separate new private output and the empty envelope. Require
a genuinely fresh executing Pod/container: the probe and readiness files must
be absent before the exact Task/Session/Pod/container acknowledgment.
An idle/predecessor Pod is not an observation for the submitted Task.

Expected useful result: new allowed receiver payload and successful write.
Expected empty result: actual EPERM/EACCES, no governed payload, working
unrestricted receiver controls. Preserve intentional failed initialization or
evaluation separately. Overall success also requires exact cleanup.

The fixed link-local test endpoints/ports are declared by the policy and fixtures;
they are not implicit production grants. The external model bridge is trusted
and outside the governed target. The bind gateway is explicitly configured,
not a private machine's hardcoded address.

## kagent model-free probe

`tools/poc/build-running-probe.py` prepares two **test-only** overlays and builds
the published network-independent workload, app fixture and compute fixture.
It does not change production gate/policy source, run a workload or synthesize
an inference answer. See `examples/poc/kagent/fixture-overlays/` and the source
for the exact changed assertions and receiver-ready handshake.

Use new output, admitted local caches and the public source lock:

```sh
python3 "$DOCS/tools/poc/build-running-probe.py" \
  --sources "$SRC" --manifest "$DOCS/docs/poc/sources.json" \
  --out "$POC/kagent-probe-build-01" --go "$(command -v go)" \
  --module-cache "$GOMODCACHE" --build-cache "$GOCACHE"
```

Run the source-documented native app/compute fixture with
`EXECUTION_NATIVE_NETWORK_INDEPENDENT=1` and
`EXECUTION_PUBLIC_NATIVE_SCENARIO=allow` or `empty`, supplying its declared
guest/control/TLS/binary inputs from the [fixture index](fixtures.json).
The workload waits for real receiver readiness over ordinary control stdio;
it then attempts the authored raw endpoint. Evaluation remains deliberately
failed. Require the actual syscall record and receiver counts, not that failure
alone.

Sessions uses its separate public Session/harnesswire native fixtures and its
matching Substrate controller. The kagent overlays are not portable aliases
for the Sessions fork.

## Attribution and limits

Original project licenses/headers remain with the sources. The static seccomp
example is derived from containerd's Apache-2.0 default profile; the accompanying
generator shows the exact clone3 adjustment. It is not the OpenShell profile.
Build-profile image references identify test source inputs; no opaque VM or
runtime image is published in this repository.

These publication-adjusted helpers/templates have not been run on a newly
provisioned cluster just because their source is available. Their earlier
observations and current source-build scope remain distinct.
