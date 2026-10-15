# Security model

The Ed25519 signing seed must be a regular root-owned file with no group/world permission bits. No environment or development fallback exists. Unix transport authenticates peers with `SO_PEERCRED`; signed descriptors additionally bind operator-pinned provider ID, endpoint ID, algorithm, key ID/key, minimum epoch, and freshness.

Activation success is not proof. The packaged `LinuxBPFAdapter` advertises `filesystem/deny-write/v1` only while two pinned maps and all fifteen pinned LSM links are independently queryable. A generation derived from activation identity and desired configuration namespaces each policy. Exact `(device,inode)` path entries are installed before the exact cgroup target entry, so a partial activation cannot enable an empty policy. Kernel readback verifies target generation, every policy value, every attached link, and every current path identity. Removal of any required object revokes capability advertisement or fails readback.

The policy covers listed roots and descendants existing at activation. Mutation hooks on protected parent directories deny creating, linking, renaming, or symlinking new entries beneath them; hooks on protected inodes deny writable opens, writes, truncation, metadata changes, unlink, and mount bypass. Exact cgroup targeting ensures unlisted paths and non-target cgroups are unaffected. Privileged positive, negative, bypass, restart, and cleanup tests exercise these boundaries.

Startup reconciles provider, backend, and kernel inventories. Missing desired/live attachments fail closed and live orphans are detached. Cleanup requires a durable released state and disables the target before deleting policy entries. Rollback or cleanup ambiguity quarantines the backend. Exact altered retries conflict after restart.
