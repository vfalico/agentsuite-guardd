# Operations

Run `packaging/install.sh` as root. It installs the Python application and its
dependencies into the dedicated `/opt/agentsuite-guardd/venv` environment,
links only the service entry point into `/usr/local/bin`, creates a random
32-byte root-owned mode-0600 credential if absent, installs configuration, the
Gadget loader, and both systemd units, and never prints the credential. It does
not modify the distribution-managed Python environment.

The prerequisite `agentsuite-guardd-gadget.service` compiles the delivered BPF source against host BTF, verifier-loads and attaches all fifteen LSM programs, and pins `guarded_targets`, `guarded_paths`, `filesystem_denials`, and every link under `/sys/fs/bpf/agentsuite-guardd`. It repairs missing links and upgrades programs by loading a complete replacement set against the existing pinned maps before replacing link pins, so active target and policy entries remain intact. Incomplete maps are rebuilt only when the guarded-target map is empty; otherwise startup refuses the unsafe replacement. It also refuses missing BPF LSM, bpffs, clang, bpftool, or unsupported architecture. The provider unit requires this prerequisite.

The gadget unit grants its mount namespace write access to the bpffs mount
root because systemd resolves `ReadWritePaths` before the loader can create the
provider's first-run pin directory. The loader itself remains scoped to
`/sys/fs/bpf/agentsuite-guardd` and never writes sibling pin trees.

The service runs `agentsuite-guardd --config /etc/agentsuite-guardd/config.json serve`, binds a mode-controlled Unix socket, and remains foregrounded. `LinuxBPFAdapter` advertises the filesystem capability only while all pinned maps/links can be queried. It resolves policy roots and existing descendants to `(device,inode)` identities, writes all generation-scoped policy entries, then enables the exact target cgroup. Readback queries the kernel maps and restats every path; it does not trust desired-state JSON as evidence.

On startup, provider SQLite activation inventory, backend desired inventory, and live adapter inventory must agree. Live orphans are detached; missing live state, changed path identity, map divergence, or missing links quarantine startup. Cleanup first persists the exact attempt, activation, and cleanup identity with a `cleaning` intent, removes the target before generation policy entries, and then persists `cleaned`; startup resumes only that persisted cleanup identity. Legacy or incomplete cleaning state quarantines rather than guessing. Never delete state or pins to force release.

Changed retries conflict unless the complete persisted identity is exact. Monitor descriptor freshness, socket liveness, quarantine results, map/link pins, pending operations, and cleanup. Missing credentials, loose permissions, unsupported capabilities, stale authorization, and absent/mismatched backend state fail closed.
