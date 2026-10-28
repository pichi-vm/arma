#!/usr/bin/env python3
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Refresh the committed Cargo sources and notices using matching rust-src."""

import os
from pathlib import Path
import shutil
import subprocess
import tomllib


repo = Path(__file__).resolve().parent.parent
sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
library = sysroot / "lib/rustlib/src/rust/library"
if not (library / "Cargo.lock").is_file():
    raise SystemExit("install matching Resolute rust-src; see debian/README.source")

config = subprocess.check_output(
    ["cargo", "--config", "net.offline=false", "vendor", "--locked",
     "--versioned-dirs", "--sync", str(library / "Cargo.toml"), "vendor"],
    cwd=repo, env={**os.environ, "RUSTC_BOOTSTRAP": "1", "CARGO_NET_OFFLINE": "false"},
)
lock = tomllib.loads((repo / "Cargo.lock").read_text())
pins = sorted({crate["source"] for crate in lock["package"]
               if crate.get("source", "").startswith("git+")})
header = "# Git revisions pinned by Cargo.lock:\n" + "".join(f"# {pin}\n" for pin in pins)
(repo / ".cargo/config.toml").write_text(
    header + config.decode() + "\n[unstable]\nbindeps = true\n\n[net]\noffline = true\n"
)
shutil.copyfile(library / "Cargo.lock", repo / ".cargo/rust-src.lock")

with (repo / "LICENSE.dependencies").open("w") as notes:
    notes.write("Bundled crates from Cargo.lock and rust-src.lock; original license choices retained.\n")
    for manifest in sorted((repo / "vendor").glob("*/Cargo.toml")):
        crate = tomllib.loads(manifest.read_text())["package"]
        notes.write(f"\n{'=' * 72}\n{crate['name']} {crate['version']}\n")
        notes.write(f"License: {crate.get('license', crate.get('license-file', 'unspecified'))}\n")
        notes.write(f"Authors: {', '.join(crate.get('authors', []))}\n")
        for path in sorted(manifest.parent.rglob("*")):
            if path.is_file() and path.name.lower().startswith(
                ("license", "copying", "notice")
            ) and path.name != "licenserc.toml":
                notes.write(f"\n--- {path.relative_to(manifest.parent)} ---\n")
                notes.write(path.read_text())
                notes.write("\n")
