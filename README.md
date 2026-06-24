# arma

The PMI producer for pichi-vm. `arma build` turns a kernel (+ optional initrd
and cmdline) into a [Portable Machine Image](https://github.com/pichi-vm/pmi):
a single PE carrying the base platform devicetree, the `tatu` boot stub as
firmware, and the kernel — booted by a PMI VMM such as dillo.

This repository bundles `tatu` (the guest-side PMI boot stub, built bare-metal
and embedded as an artifact) and its `dtb2acpi` / `dtb2e820` helpers.

## License

Apache-2.0 — see [LICENSE](LICENSE).
