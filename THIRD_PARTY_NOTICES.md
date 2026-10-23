# Third-party notices

AgentSuite Guardd depends directly on **cryptography 46.x**, distributed under
Apache License 2.0 or BSD-3-Clause at the recipient's option. The distribution
uses cryptography's Ed25519 primitives for authenticated descriptors and proofs.
See <https://cryptography.io/> and the installed distribution's `LICENSE.APACHE`
and `LICENSE.BSD` files for the complete license texts.

On CPython platforms where the selected cryptography wheel/runtime requires it,
**cffi** is a transitive runtime dependency distributed under MIT; cffi in turn
uses **pycparser**, distributed under BSD-3-Clause. Platform-specific wheels may
bundle additional Rust/OpenSSL components; their authoritative notices are in
the wheel's `cryptography-*.dist-info/licenses/` directory. Package installers
must preserve those files.

The Go runtime adapter uses the Go standard library only. The external Gadget is
built against public Linux eBPF and Inspektor Gadget OCI Gadget interfaces;
those dependencies are not vendored in this source archive.

The public PoC's `examples/poc/orka/held-seccomp.json` is derived from
containerd's default seccomp profile, distributed under Apache License 2.0.
The accompanying generator source preserves that attribution and shows the
explicit clone3 adjustment. See <https://github.com/containerd/containerd>
and this distribution's Apache-2.0 `LICENSE`.
