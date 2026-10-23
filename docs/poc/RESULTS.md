# What was demonstrated

These are **bounded observations recorded before publication**, not a new run
of this public checkout, a formal proof, an independent certification or a
claim that every upstream test suite passed. Original traces and private
execution records are intentionally not redistributed.

| Layer | Observed behavior | Boundary |
|---|---|---|
| Three public runtime paths | Kaimahi propagated complete requirement identity into Orka, Agent Sessions and kagent; ordinary native status/result paths were exercised | Selected Linux lanes and pinned integration sources, not all runtime backends |
| Useful policy | Real allowed payloads and real forbidden native attempts with working independent controls | No inference-quality or general-internet claim |
| Empty allowlist | Running native probes attempted egress and were denied in all three runtime families | Intentional failed inference/evaluation remains failed; denial is proved by syscall/receiver observations, not status alone |
| Owning gates | Hold-before-first-effect, activation failure, cancellation, replacement and original-operation cleanup | Controlled gate tests prove runtime decisions, not the kernel by themselves |
| Shared native backend | Actual kernel protection, exact-handle transport, inherited/delegated descriptor discriminators | Tested target classes/profiles, not an exhaustive syscall/architecture matrix |
| Lifecycle | Dropped replies, same-operation reconciliation, daemon loss/recovery, overlapping bindings, exact retirement and surviving unrelated protection | Layered host/guest mechanisms; not every public API race was repeated |
| Genericity | Independent non-Suite peer through ordinary configured owning gates | Wiring/hold/refusal/retirement only; fake peer is not a network enforcer |
| Policy-free behavior | No mandatory peer on requirement-free execution | Does not authorize stripping a requirement from a governed execution |
| Source delivery | Exact bases plus ordered changes reconstruct the selected implementations; source builds were separately recorded | A source build is not native execution or identical rebuilt binary identity |

## Explicit nonclaims and retained limitations

- Not production rollout approval, a reviewed upstream abstraction, universal
  platform support, performance/load certification or paid-model quality proof.
- Not a self-provisioning fresh-host installer. Public source/build recipes
  still require explicit compatible kernel, guest, userspace, VM and cluster inputs.
- Not complete filesystem or ingress enforcement. The PoC's advertised runtime
  lane is the supported network ceiling.
- Not retrospective removal of buffered or already-in-flight data, nor a ban on
  all handshake/control packets. New governed application data is the boundary.
- Not proof for every TFO/TLS, fragmentation, io_uring, delegation, privileged
  broker or restore mechanism.
- A host TAP-only boundary was insufficient for guest loopback. It is refused
  as a complete target; guest-visible enforcement remains necessary.
- Some earlier cleanup/recovery attempts failed or timed out. Later successful
  retries do not establish the cause of the first timeout. Power-loss,
  resource-exhaustion, rolling upgrade/leader replacement and some deletion
  finalizer completion remain unproved operational surfaces.
- Skipped/unavailable-capability cases are not passes. Successful component
  runs do not erase prior failures or qualify a different source/image/kernel.
- Publication changed fixture coordinates, resource labels and documentation,
  not runtime enforcement logic. The adjusted helpers and new setup tooling
  have not been freshly native-qualified merely by being published.

## Known separate Orka drain issue

The frozen integration contains an over-restrictive never-enrolled drain guard.
An empty pending preparation can keep a drain blocked. The independent comparison
favored [orka-agents/orka#922](https://github.com/orka-agents/orka/pull/922):
eight controller-fixture cases passed there, versus six for the stricter
candidate and four on the original comparison base. Committed preparation and
interrupted witness publication recover before the ordinary fallback.

That comparison concerns controller enrollment/drain, not native network
enforcement or live Kubernetes leader failover. This frozen PoC **does not
silently incorporate that separate correction** or claim its qualification.
Use the preferred correction when preparing subsequent integration/rebase work;
do not weaken actual retained Pod/witness/ownership fences.
