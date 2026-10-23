# Design feedback and future rework

This branch publishes the working reference so its behavior and costs can be
discussed. It is deliberately **not** the proposed shape of an upstream PR.
Mechanical commit splitting would not make the current architecture agreed.

The Orka discussion
[orka-agents/orka#831](https://github.com/orka-agents/orka/pull/831#issuecomment-6321068442)
asks for a concise user story and a thin, generic end-to-end slice.
The current PoC aligns on opaque whole-requirement handling and real execution
wiring, but differs substantially:

| Topic | Frozen PoC | Direction needing design agreement |
|---|---|---|
| Execution identity | Per-execution process/cgroup; requirement deliberately not pool configuration | Dedicated initial session/container and requirement-bound pool identity |
| Trusted client | Protected privileged socket mounted into the runtime Pod | Trusted node-local client outside governed Pod or controller-to-node mTLS |
| Release ownership | Orka prepares and releases a held process after provider activation/readback | Also support providers that gate container startup themselves and publish evidence |
| State | Local association/recovery journals and cleanup-only checkpoints | Existing runtime lifecycle status under epoch/attempt fences |
| Pod shaping | Specific HostPath, cgroup, Localhost seccomp and capability requirements | Provider-neutral extensible policy/security compatibility |
| Policy reference | Inline bounded immutable policy bytes | Also allow provider-managed names with digest/revision identity |
| Capability assessment | Runtime interface accepts a target class, but the neutral assessment wire does not forward it | Execution-path-specific capability checks; activation must still refuse unsupported exact targets |
| User-visible evidence | RuntimeSession enforcement state | Coherent Task/Session enforced-versus-observed evidence |

Changing the execution boundary or trusted-client placement can invalidate
assumptions in lifecycle, persistence, preparation and cleanup. Treat rework as
a separate design and qualification effort, not a renamed copy of this patch.

OpenShell illustrates why container identity, process-level filtering and
trusted supervisor placement must be considered independently. Its layered
approach does not automatically validate shared pools or privileged socket
placement here. No compatibility or equivalence with OpenShell is claimed.

Useful feedback: the smallest generic lifecycle contract, exact trust boundary,
initial supported runtime lane, provider-owned versus runtime-owned gating,
status/persistence ownership and what evidence belongs in public runtime APIs.
Keep future changes separate from the frozen source lock.
