# Selected modules in generated initramfs

## Goal

Extend the static-ELF `arma build --initrd` path to package explicitly
selected kernel modules and their hard dependencies for an init such as
Corium. Decode every selected module on the host, including its hard
dependencies, storing plain `.ko` files in the archive. Complete
archives are validated without rewriting, rejecting compressed modules.
Do not change PMI, Corium, or unrelated security and interrupt behavior.

## Interface

```
arma build --kernel vmlinuz --initrd corium \
    --module virtio_pci --module virtio_blk --module dm_verity \
    --cmdline 'corium=...' guest.pmi
```

`--module NAME` is repeatable. Each original name must match the full-string
ASCII allowlist `\A[A-Za-z0-9_][A-Za-z0-9_-]*\z` before hyphens are normalized
to underscores for lookup. Names are not paths, filenames, aliases, globs,
or module parameters.

`--module-tree PATH` optionally identifies the actual release-specific
module directory, not a rootfs. Without it, detect the supplied kernel's
exact release and look in `/usr/lib/modules/<release>` and
`/lib/modules/<release>` in the root filesystem. Canonical aliases count
as one directory; distinct candidates are ambiguous. Never use the host's
`uname`, the kernel filename, the newest directory, or a lone tree as a
substitute for detecting the target release. Explicit trees override only
the source; the archive directory still uses the target release. Releases
are bounded printable ASCII path components, preserving local/distro suffixes
without normalization; slash, backslash, colon (host drive prefixes), whitespace,
and the special components `.` and `..` are rejected. This restriction applies
only to the release token. The bounded Linux banner's builder/compiler metadata
is treated as opaque bytes and may contain UTF-8 or other non-ASCII data;
parenthesized build-identity structure and NUL-termination bounds are still
checked.

Module options require a static ELF init. Reject an explicit tree without
selections, module selections without an init, and module options with a
complete archive, compressed or otherwise. No selections means no release
lookup or module-tree discovery. Complete archives are checked for compressed
module names anywhere; any `.ko.<extension>` filename with a nonempty
extension fails the build, including unknown formats.
Arma does not rewrite supplied archives. Plain modules in supplied archives
pass through as supplied.

## Resolution and packaging

Read mandatory `modules.dep` and `modules.builtin` from the selected tree. Resolve
named roots plus their transitive loadable hard dependencies; built-in
roots require no payload. Reject missing or ambiguous requested names. Other
names may repeat: dependencies identify files by their full relative paths.
Reject broken references, cycles, malformed metadata, and unsafe paths. Validate
the entire index, including unselected definitions and referenced files, rather than
silently ignoring a broken tree. Deduplicate and sort the result. Do not
require host `modprobe` or `depmod`. An all-built-in selection is valid and
produces the ordinary static-init archive with no module payloads.

Because the entire index is validated, even an unselected symlink or stale
file reference causes failure. Trees using layouts such as symlinked
`weak-updates` entries must instead be prepared as regular-file staging trees
with consistent indexes. Such a staging tree may have an arbitrary directory
name; its basename is not used as evidence of the target release or module ABI.

Accept only regular `.ko`, `.ko.xz`, `.ko.gz`, and `.ko.zst` module files.
Reject file symlinks, traversal, special files and dependencies escaping
the canonical module tree. Default discovery may follow the normal
`/lib` to `/usr/lib` directory alias. Preserve relative subdirectories under
`usr/lib/modules/<exact-release>/`. The source is a trusted,
read-only tree for the duration of the build. Standard filesystem checks reject
existing symlinks and escapes but are not an atomic sandbox against concurrent
malicious replacement of files or directories.

Keep the existing `/init`, `/dev`, and `/dev/console` archive entries. Add
parent directories deterministically, normalize metadata, enforce newc
field bounds and build the complete archive before guest layout planning.
Do not ship module index files; Corium recursively loads eligible regular
files without reading those indexes. Print the target release, chosen
source tree, built-in selections, and included files, distinguishing roots
from dependencies.

Require `CONFIG_MODULES=y` for loadable payloads, using `--config` or
embedded IKCONFIG. Always decode `.ko.gz`, `.ko.xz` and `.ko.zst` on the
host to plain `.ko`, regardless of guest decompressor options. Preserve
plain and decoded bytes exactly, including appended signatures; do not
strip or re-sign. Reject unsupported suffixes, magic mismatches and malformed
streams before writing output, preserving an existing destination on failure.
Limit combined output across concatenated streams to 64 MiB per module;
cap XZ memory and zstd windows at 64 MiB. Decode only selected payloads.
Source trees are read-only inputs. Release matching does not prove ABI,
modversion or signing compatibility.

The first version does not implement firmware collection, module parameters,
modprobe configuration, aliases, softdep ordering, or runtime-requested
module discovery. Hard-dependency closure is not a complete bootability
guarantee. Select other required modules explicitly. This is a packaging
allowlist, not kernel-wide runtime load enforcement. Arma supplies no
Corium/Fedora-specific driver policy. Existing explicit slot/config rules
remain unchanged when a transport is modular.

## Implementation boundaries

- `kernel_release`: release detection on the normalized kernel before ELF
  metadata is discarded, using `linux_banner` when available and bounded,
  unambiguous banner fallback for supported stripped/raw images.
- `modules`: CLI name validation, discovery, metadata parsing, dependency
  resolution, safe file inventory and bounded host decompression.
- `initrd`: bounded deterministic newc emission, without changing archive
  pass-through.
- `kconfig`: built-in module configuration check.
- `main` and `build`: argument validation and orchestration before PMI layout.

## Acceptance criteria

1. Original module names use the allowlist regex; punctuation, whitespace,
   Unicode, paths, suffixes, globs and parameters are rejected before lookup.
2. Target releases retain distro/local suffixes; missing, unsafe and ambiguous
   release data fails. Real x86 and arm64 inputs exercise extraction after the
   existing wrapper normalization. No-module builds remain unaffected.
3. Explicit source override and default discovery work; aliases deduplicate;
   distinct trees and missing matching trees fail deterministically.
4. Built-ins, normalized names, shared/transitive dependencies, repeated roots,
   missing files, ambiguous names, malformed metadata and cycles are tested.
5. Traversal, symlinks, nonregular files and unsupported suffixes are rejected.
6. Archive entry paths, modes, ownership, timestamps, byte preservation,
   unconditional decompression, signature preservation, size bounds and
   determinism are tested. Unsupported formats and compressed modules inside
   supplied archives fail without replacing output.
7. CLI tests exercise valid selections and incompatible/negative inputs;
   inspect the PMI initrd payload and DTB initrd extent, not just CLI status.
8. A real matching kernel/module set is packaged. An actual Corium VM run
   verifies the module phase with a required modular driver and explicit guest
   shutdown. Any unavailable VM/full-handoff prerequisite is recorded rather
   than represented as successful integration.
9. Formatting, warnings-denied Clippy/build/workspace tests, and dependency-policy
   checks pass.
