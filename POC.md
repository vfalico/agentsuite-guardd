# Whole-requirement enforcement PoC

**Experimental, source-pinned reference implementation. Not a production release
or an upstream-ready patch series.**

The same immutable AgentSuite network requirement travels through Kaimahi into
Orka, Agent Sessions or kagent. The owning runtime holds execution until Guardd
has activated and independently read back protection for the exact target.
Empty allowlists remain empty; model, proxy and control endpoints are not
silently added.

Start at **[the PoC guide](docs/poc/README.md)**:
source checkout, builds, native prerequisites, reproduction, experimentation,
demonstrated results and known limitations. No private infrastructure, original
execution traces, credentials or prebuilt VM images are required or distributed.
Native experiments do require a separately provisioned disposable Linux setup.

The default Guardd branch and existing upstream PRs are separate from this PoC.
Feedback and subsequent design work must not be confused with this frozen version.
