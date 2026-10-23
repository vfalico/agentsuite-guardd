# Components and trust boundaries

```text
AgentSuite policy / workspace
            |
       Kaimahi (kmx)
            | complete immutable requirement
       +----+-------------------+------------------+
       |                        |                  |
     Orka                  Agent Sessions        kagent
       |                        |                  |
 ACP supervisor          Sessions Substrate   kagent Substrate
       |                        |                  |
 held process/cgroup      prepared microVM    prepared microVM
       |                        |                  |
       +------ exact target -> Guardd <-----------+
                          |
                native kernel enforcement
```

The enforcement **provider** is Guardd, not the LLM provider. A small independent
test peer exercises the generic protocol without providing kernel protection.

## Built, modified and unchanged

| Component | Role | PoC change |
|---|---|---|
| AgentSuite | Portable policy model, canonical effective semantics and identity | Unchanged; exact source pinned |
| Kaimahi | Resolves Suite intent and submits through ordinary runtime APIs | Modified; carries complete immutable requirements and native result bindings |
| Orka | Owns Tasks, RuntimeSessions, ACP execution, stop and cleanup | Modified; generic requirement/client, held-process gate, configuration and recovery |
| ACP supervisor | Trusted Orka runtime process around the ACP adapter/agent | Existing supervisor modified; generic Unix adapter and cleanup journal added, not a separate upstream project |
| Agent Sessions | Public Session API, durable journal and runtime lifecycle | Modified; frozen requirements, original-operation ownership, exact resume and governed cleanup |
| kagent | Public agent/session execution and owning Actor lifecycle | Modified; requirement propagation, generated APIs and explicit cold-start lane |
| Both Substrate variants | Actual prepared compute, guest control and lifecycle | Modified independently on different upstream bases; prepare/activate/release/stop fencing and guest transport |
| Guardd | Interprets the whole requirement and binds enforcement to exact targets | Owner-developed provider; native/network backend and neutral lifecycle/guest transport extended for this PoC |
| Linux BPF/cgroups, libbpf, Kata/Cloud Hypervisor, Kubernetes | Kernel, VM and orchestration foundations | Used as dependencies, not rewritten; the guest kernel configuration is customized |
| Native probes and independent peer | Reproduce scoped lifecycle and network observations | Test tooling, not a production enforcement engine |

Generated CRDs/protobuf/client changes are included with their owning source.
The source snapshots combine API, runtime, recovery and test work; they are
not fifteen independent upstream-ready PRs.

## Lifecycle

1. Kaimahi resolves a complete immutable effective requirement.
2. The runtime freezes it into its execution intent before creation.
3. The owner prepares a non-running exact target and retains its operation.
4. The provider checks support, activates and independently reads back the
   exact requirement/target/generation.
5. Only the runtime releases execution. A healthy socket or support response
   is not release authority.
6. The runtime stops compute, establishes stable emptiness and retires the
   same binding. Lost replies retain original-operation ownership.
7. Uncertainty is cleanup-only or refusal, never policy-free continuation.

No runtime parses Guardd's concrete policy schema to infer extra endpoint grants.
Requirement-free execution bypasses the mandatory-enforcement lane.

## What is governed

Orka's supervisor remains trusted; the agent and descendants run in an
execution cgroup. The trusted supervisor receives a protected host-mounted
Unix socket/configuration directory and cgroup access. These are significant
trust assumptions, not merely a convenient transport detail.

For the VM lanes, a host TAP-only filter cannot cover guest loopback or other
guest-local traffic. The complete boundary is guest-visible: a supporting guest
kernel, guest Guardd service and exact runtime preparation/release protocol.
The retained interface implementation is diagnostic/cleanup compatibility;
it is refused as a complete-policy activation target.

Dedicated container identity, process-level kernel attachment and trusted-control
placement are **different axes**. Process-scoped enforcement does not by itself
justify policy-independent shared pools, exposing a privileged provider socket,
or treating the whole supervisor as untrusted.

The advertised ceiling concerns **new governed application egress after
activation**. It does not erase already-buffered/in-flight data, forbid all TCP
control packets, or claim to govern external trusted model/control brokers.
