# Initramfs fixtures

`initramfs.cpio` is a complete GNU cpio newc archive containing an executable
`init` with these bytes (including the final newline):

```sh
#!/bin/sh
printf 'arma initramfs fixture\n'
exec /bin/sh
```

It is an archive-format fixture, not a self-contained bootable userspace (there
is no `/bin/sh`). The image tests verify ingestion and PMI bytes, not execution.

Generated with GNU cpio, gzip and zstd, not required at test runtime:

```sh
# In a directory containing only the executable init shown above:
printf 'init\n' | cpio --create --format=newc --reproducible > initramfs.cpio
gzip -n -c initramfs.cpio > initramfs.cpio.gz
zstd -q -f initramfs.cpio -o initramfs.cpio.zst
```

cpio metadata includes the source file's mtime, so regeneration need not produce
identical bytes. Both compressed fixtures decode to the committed archive.

## Compressed module fixtures

`module.ko.gz`, `module.ko.xz`, and `module.ko.zst` all decode to the bytes
`b"\x00module payload\xff\n"`. These synthetic bytes exercise packaging,
not the module ABI. The XZ fixture uses a SHA-256 checksum, as used by
kernel module compression. Tests need no external compression programs.

Generate them with Python 3 and zstd:

```python
import gzip
import lzma
from pathlib import Path
import subprocess

payload = b"\x00module payload\xff\n"
Path("module.ko.gz").write_bytes(gzip.compress(payload, mtime=0))
Path("module.ko.xz").write_bytes(lzma.compress(payload, check=lzma.CHECK_SHA256))
Path("module.ko.zst").write_bytes(subprocess.run(
    ["zstd", "-q", "-c"], input=payload, check=True, capture_output=True,
).stdout)
```
