# Short guide for coding assistants

Read `README.md`, `ARCHITECTURE.md`, `RESULTS.md` and the relevant source's
`AGENTS.md` before editing. This is an experimental, frozen PoC; create a new
rework branch rather than changing its source lock.

- Source authority: `sources.json`, exact commit **and** tree. Branch names are
  navigation, not a replacement for pins.
- Publish only to explicitly authorized `vfalico` destinations. No upstream
  PR, comment, branch, issue or release operation is implicit.
- Keep canonical Go imports. Kagent and Sessions Substrate share a module path
  but require separate branches, checkouts and workspaces.
- Suite is unchanged. Kaimahi resolves intent. The runtime owns target,
  release/stop/cleanup. Guardd interprets and enforces the complete requirement.
- Support/readiness is not activation. Uncertainty cannot release. Lost replies
  retain original-operation and exact-target ownership.
- No silent endpoint additions, DNS/proxy exceptions or policy-free fallback.
- Fake peer proves wiring, not kernel enforcement. Compilation is not runtime
  acceptance; skipped prerequisites are NOT RUN.
- Actual native experiments require disposable, admitted Linux resources.
  Never start privileged workloads, paid-model evaluations or deployments just
  to inspect/build this source.
- Keep original/current/new binary, image and kernel identities distinct.
  Publication-only fixture changes do not imply a fresh native result.
- Preserve exact cleanup ownership; never clear journals, pins or restrictions
  to make a rerun appear clean.
- No credentials, private kubeconfig, raw traces, private infrastructure or
  workstation assumptions in public commits.

`fixtures.json` is the machine-readable native-test/input index.
`tools/poc/checkout.py --check` is local manifest validation only.
