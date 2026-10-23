# Whole-requirement enforcement: public PoC

**One policy, three owning runtimes, no implicit grants.**
This is a development reference, not a stable API, production deployment or
merge-ready upstream proposal.

| Start here | What it answers |
|---|---|
| [Architecture](ARCHITECTURE.md) | Components, trust boundaries, what changed |
| [Setup](SETUP.md) | Exact sources, toolchain, dependencies and builds |
| [Reproduce and test](TESTING.md) | Fast checks, native experiments, expected results |
| [Native fixture recipes](FIXTURES.md) | Guest image, model-free probe and explicit cluster inputs |
| [Demonstrated results](RESULTS.md) | Observed behavior versus what is not proved |
| [Design notes](DESIGN.md) | Known integration costs and questions for rework |
| [AI guide](AI.md) | Short operating contract for coding assistants |
| [Source lock](sources.json) | Machine-readable exact commits and trees |
| [Fixture index](fixtures.json) | Native test names, opt-in variables and source locations |

## Get the source

```sh
git clone --branch poc/whole-requirement-v1 --single-branch \
  https://github.com/vfalico/agentsuite-guardd.git guardd-poc-docs
python3 guardd-poc-docs/tools/poc/checkout.py --check
python3 guardd-poc-docs/tools/poc/checkout.py --root "$PWD/enforcement-poc"
```

The second command only validates the source lock. The third downloads the eight
exact source snapshots and writes **external** Go workspaces. It runs no tests,
workloads, image builds, installers or cloud commands. It requires a new directory
and sufficient local headroom.

All publication destinations are under `vfalico`. Substrate has **two distinct
branches and checkouts**, not two interchangeable dependencies. Canonical
Go module/import paths remain unchanged.

## What to expect

Read and build without root. Test the protocol/owning gates without claiming
kernel protection. Use a disposable, capability-admitted Linux host for actual
BPF, cgroup, microVM or Kubernetes experiments. Source acquisition is automated;
native-host provisioning is deliberately not presented as a one-command install.

The source lock pins the implementation commits. Guardd's branch additionally
contains this documentation/tooling overlay, so its branch tip is newer than the
Guardd source commit in the lock. That is intentional, not source drift.
Runtime enforcement logic is frozen. Publication edits remove private fixture
coordinates and temporary labels; they are not a new native qualification run.
