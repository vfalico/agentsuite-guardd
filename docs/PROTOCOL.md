# Provider protocol

The provider ID is `agentsuite-guardd/v1`; transport version is `1`; provider protocol is `orka.enforcement-provider/v1`. Each request and response is one bounded JSON object followed by LF on a Unix `SOCK_STREAM` connection. The server authenticates the caller UID using `SO_PEERCRED`; the Orka client independently pins the server UID.

External operations are `DiscoverDescriptor`, `NegotiateCapabilities`, `Prepare`, `Activate`, `ReadBack`, `GetProof`, `Release`, `GetStatus`, `Reconcile`, and `Cleanup`. Unknown transport versions or operations fail closed. Exact policy bytes and their length-framed digest are retained.

Descriptors are Ed25519-signed and bind provider ID, endpoint identity, algorithm, key ID/key, epoch, lifetime, protocol versions, and capabilities. Orka validates the descriptor against operator-pinned trust before using its proof key. Proofs bind authorization, activation, workload, provider, audience, challenge, policy, independent readback, epoch, lifetime, and key.
