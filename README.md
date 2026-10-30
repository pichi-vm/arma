# arma

The PMI producer for pichi-vm. `arma build` turns a kernel (+ optional initrd
and cmdline) into a [Portable Machine Image](https://github.com/pichi-vm/pmi):
a single PE carrying the base platform devicetree, the `tatu` boot stub as
firmware, and the kernel — booted by a PMI VMM such as dillo.

This repository bundles `tatu` (the guest-side PMI boot stub, built bare-metal
and embedded as an artifact) and its `dtb2acpi` / `dtb2e820` helpers.

Include `bootconfig` in the guest kernel command line to request a fixed 2 MiB
`lbc:bootconfig` reservation, for example `--cmdline 'bootconfig console=hvc0'`.
The argument must precede any `--` separating kernel and init arguments. Arma
recognizes Linux's quoting and parameter-name rules, including `bootconfig=0`.

A requested reservation requires a nonempty `--initrd` and a kernel built with
`CONFIG_BOOT_CONFIG=y`, `CONFIG_BLK_DEV_INITRD=y` and `CONFIG_PROC_FS=y`.
Arma reads `--config` or embedded IKCONFIG and checks that kernel command-line
replacement, extension and truncation preserve activation. A built-in
`bootconfig` argument or `CONFIG_BOOT_CONFIG_FORCE=y` can preserve activation;
the argument supplied through `--cmdline` is what requests the reservation.

Arma pads `.initrd` to a 2 MiB boundary and places the Zero section `.bconf`
immediately after it. Linux's initrd range covers both sections. The reservation
has no on-disk payload. Without the argument, the image contains only the
padded initrd. Arma preserves the supplied command line, with the existing
`--serial` handling for `earlycon`.

The VMM supplies bootconfig at launch for Linux to expose through
`/proc/bootconfig`. The `arma cmdline` editor replaces DTB boot arguments
verbatim; changing the allocation requires rebuilding the image.

## Selected kernel modules

When `--initrd` is a static ELF (for example Corium), repeat `--module NAME`
to include named modules and their hard dependencies in the generated archive.
Arma detects the target kernel's release and discovers its installed module tree;
`--module-tree PATH` overrides the source with a release-specific directory.
See [module packaging](docs/module-packaging.md) for the interface, validation,
limitations, and acceptance criteria.

## License

Apache-2.0 — see [LICENSE](LICENSE).
