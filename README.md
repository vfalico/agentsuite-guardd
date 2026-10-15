# AgentSuite Guardd

AgentSuite Guardd is a standalone implementation of the generic Orka enforcement-provider protocol. It validates exact canonical AgentSuite policy bytes, negotiates capabilities fail closed, performs activation plus independent readback, signs authenticated descriptors and proofs, and exposes all lifecycle operations over a versioned Unix socket.

## Build and test

```sh
PYTHONPATH=src python3 -m pytest
(cd adapter && go test -race ./...)
python3 -m build
```

The source tree or sdist is the deployable service artifact; `packaging/install.sh` installs its host BPF and systemd payload. The wheel intentionally contains only the Python library and CLI. The packaged service reads `/etc/agentsuite-guardd/config.json`, requires a root-owned mode-0600 Ed25519 seed, restores SQLite state, reconciles live attachment records, authenticates Unix peers with `SO_PEERCRED`, and remains active at `/run/agentsuite-guardd/provider.sock`. There is no signing-key fallback.

`MemoryBackend` and `backend: conformance-memory` are explicit test-only modes. The packaged `linux-bpf` backend uses `LinuxBPFAdapter`, which advertises `filesystem/deny-write/v1` only while both pinned kernel maps and all fifteen attached LSM links are independently observable. It compiles each deny path into exact `(generation, device, inode)` entries, enables the exact cgroup target only after all policy entries exist, and reads every map entry and current path identity back from kernel state. Startup reconciles persisted provider, backend, and live-map inventories; detach removes the target first, then policy entries. If any link, map, path identity, or inventory is absent or divergent, negotiation/readback fails closed.

## Local service smoke test

```sh
install -d -m 0700 /tmp/guardd-smoke
head -c 32 /dev/urandom > /tmp/guardd-smoke/key
chmod 0600 /tmp/guardd-smoke/key
# Create a config using backend "conformance-memory" and paths under /tmp/guardd-smoke.
PYTHONPATH=src python3 -m agentsuite_guardd.cli --config /tmp/guardd-smoke/config.json serve
```

Runtime roots are `/etc/agentsuite-guardd`, `/run/agentsuite-guardd`, and `/var/lib/agentsuite-guardd`. No remote service or registry is required to build this source handoff.
