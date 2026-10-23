# Reproduce, test and explore

Use the [locked source and setup](SETUP.md). Nothing below is run automatically
by checkout. Start with the cheapest relevant layer; do not interpret skips,
mock success or a compiler exit as native protection.

## 1. Protocol and owning-runtime checks

Install the repository's test dependencies into the disposable venv when
needed (`"$POC/venv/bin/python" -m pip install pytest build`).
Representative focused commands:

```sh
cd "$SRC/guardd"
PYTHONPATH=src "$POC/venv/bin/python" -m pytest tests

cd "$SRC/orka"
make ensure-ui-embed
GOWORK=off go test ./internal/acp ./internal/harness/v2 \
  ./workers/acp/supervisor/enforcementunix

cd "$SRC/sessions"
GOWORK="$POC/workspaces/sessions.work" go test ./runtime/substrate ./placement

cd "$SRC/kagent/go"
GOWORK="$POC/workspaces/kagent.work" go test ./core/internal/substrate

cd "$SRC/substrate-kagent"
GOWORK=off go test ./internal/executionpolicy ./cmd/ateom-microvm
cd "$SRC/substrate-sessions"
GOWORK=off go test ./internal/executionpolicy ./cmd/ateom-microvm
```

Read the selected tests before execution: a package may contain opt-in native
cases and other dependency-backed tests. Use `-run` for a smaller named case.
These commands are recipes, not a claim that broad upstream suites are green.
The [fixture index](fixtures.json) lists native test functions and environment
variables directly from the source.

Inspect the independent-peer tests in Orka's `enforcementunix` and both
Substrate `internal/executionpolicy` packages. They exercise normal configuration,
hold/activation/refusal/retirement with a separate opaque peer.
**They do not provide BPF protection.**

## 2. Real kernel experiment without a cluster

After admitting a disposable root-owned BPF/cgroup-v2 host and building the
matching object, the source includes a bounded descriptor discriminator:

```sh
sudo env PYTHONPATH="$SRC/guardd/src" "$POC/venv/bin/python" \
  "$SRC/guardd/tests/native/descriptor_probe.py" \
  /absolute/new/private-run "$POC/evidence/network.bpf.o"
```

The output directory must not exist. It compares **actual unrestricted
controls** with governed inherited/fresh TCP sockets, foreign Unix delegation,
SCM_RIGHTS reception and internal socketpairs. Expect allowed receiver payloads,
denied effects/receiver absence, internal socketpair success and exact retirement.
If an unrestricted receiver fails, the denial comparison is invalid.
This is kernel-primitive evidence, not public-runtime end-to-end evidence.

Orka additionally ships `tests/native-neutral/controller.py` and
`crash_controller.py`. Set `ENFORCEMENT_POC_WORKSPACE` to the checkout workspace.
They expect `sources/guardd`, `venv`, and the source-documented test/helper/BPF
executables under `evidence`. They run actual native supervisor/tool tests,
including exact-daemon crash/restart. Their model-backed cases require the
declared Codex/adapter inputs and may incur model cost; do not run them merely
to fetch or inspect the PoC.

The legacy live-controller fixture now requires explicit `ORKA_LIVE_KMX` and
`ORKA_LIVE_CONTEXT` instead of a private machine's hardcoded path/context.
It is not a turnkey arbitrary-cluster setup.

## 3. Real VM and public-runtime experiments

Use the **matching** Substrate fork's `tests/native-tools/README.md`.
Its `controller.py`/`boundary_crash_controller.py` compile and drive the native
public Session/control/compute fixtures; the corresponding test sources expose
required binaries, guest assets, TLS and explicit opt-in variables.
Both forks retain separate fixtures because their control/runtime bases differ.
Set `REQUIRE_DOCKER=true` for dependency-backed fixtures. Missing Docker,
envtest, assets or capabilities is **NOT RUN**, never a pass.

For public Kaimahi flows inspect:

- Kaimahi `internal/kmx/app/suite_public_native_integration_test.go`,
  `suite_kagent_native_a2a_test.go` and `suite_native_denial_test.go`;
- kagent `go/core/pkg/app/native_app_test.go` and
  `go/core/internal/a2agateway/native_public_test.go`;
- Orka's ordinary node-local configuration and the included parameterized
  public Orka running-probe source.

The fixture index records their opt-in variables. Provision through ordinary
runtime APIs; do not inject status, call private release helpers or grant
endpoints solely to make a test green.
The public Orka running-probe recipe is in [the fixture guide](FIXTURES.md).
It is a publication-adjusted source recipe, not a newly run cluster acceptance.

## 4. Expected observations

| Scenario | Required observation |
|---|---|
| Useful complete policy | Allowed **new payload arrives**; an attempted unlisted effect is denied and absent at a working receiver |
| Empty allowlist | A real released/native workload attempts new egress and gets EPERM/EACCES, with no governed payload at a working receiver |
| Malformed, unsupported or uncertain requirement | No release/first workload effect; explicit refusal, not a policy-free fallback |
| Cancellation before release | No helper/workload effect; cleanup belongs to the original operation |
| Lost activation reply / daemon restart | Exact lookup/retry, restrictions retained, no second uncontrolled execution |
| Overlapping bindings | Retiring A does not unprotect B |
| Governed unsupported restore/fork/warm reuse | Refusal before effects, not inherited authority from an older incarnation |
| Requirement-free execution | Existing behavior works without a required enforcement peer |
| Cleanup | Exact compute stopped, same binding retired, no owned pin/link/target residue; unrelated execution preserved |

The useful and empty cases must use the same intended boundary and comparable
controls. A timeout, failed inference or absent receiver **alone** is not denial
proof. The network-independent fixtures intentionally may leave inference or
evaluation Failed while proving a real native syscall result. Preserve both
facts; do not rewrite runtime status to manufacture evaluation success.

## 5. Play with it

Start by changing a disposable policy's one explicit IPv4/TCP endpoint, then
compare useful and empty allowlists. Recompute canonical requirement bytes,
framed digest and identity through the Suite/Kaimahi path; do not patch a digest
or reuse a stale target identity. Include every intended model/proxy/control
endpoint explicitly; there is no implicit DNS allowance.

Try missing peer, wrong capability, changed generation, dropped response,
cancel-before-release and two simultaneous bindings. Use a fresh operation and
fresh target after a changed requirement. Keep semantic tests separate from
model quality, throughput and production availability.

## Cleanup and evidence

Stop exact owned compute before retirement. Retain the same operation, UID,
generation, state DB and journals across retry. Never erase enforcement state,
remove finalizers, signal processes by name or broadly prune containers/cgroups.
If target death or cleanup is uncertain, retain protection and report the failure.

For your run record source commits, tool versions, kernel/config/image/object
hashes, authored policy, receiver controls, exact runtime result and cleanup.
Keep secrets and kubeconfigs separate and private. This publication deliberately
does not redistribute original traces or claim a fresh run of these recipes.
