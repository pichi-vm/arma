// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Selected modules through the real CLI, PMI payload, and base DTB.
mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use devtree::{NodeView, Tree, TreeView};
use tempfile::TempDir;

fn static_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    elf
}

fn entries(mut bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut result = BTreeMap::new();
    loop {
        assert_eq!(&bytes[..6], b"070701");
        let field =
            |a, b| usize::from_str_radix(std::str::from_utf8(&bytes[a..b]).unwrap(), 16).unwrap();
        let size = field(54, 62);
        let len = field(94, 102);
        let name = std::str::from_utf8(&bytes[110..110 + len - 1])
            .unwrap()
            .to_owned();
        let start = (110 + len + 3) & !3;
        if name == "TRAILER!!!" {
            break;
        }
        assert!(
            result
                .insert(name, bytes[start..start + size].to_vec())
                .is_none()
        );
        bytes = &bytes[(start + size + 3) & !3..];
    }
    result
}

fn build(
    kernel: &Path,
    config: &Path,
    init: &Path,
    tree: &Path,
    out: &Path,
    names: &[&str],
) -> Output {
    let mut command = Command::new(common::arma_bin());
    command
        .arg("build")
        .arg("--kernel")
        .arg(kernel)
        .arg("--config")
        .arg(config)
        .arg("--initrd")
        .arg(init)
        .arg("--cmdline")
        .arg("console=hvc0")
        .arg("--module-tree")
        .arg(tree);
    for name in names {
        command.arg("--module").arg(name);
    }
    command.arg(out).output().unwrap()
}

#[test]
fn selected_modules_and_dependencies_reach_pmi_deterministically() {
    let (kernel, base_config) = common::host_kernel().expect("real kernel and config available");
    let temp = TempDir::new().unwrap();
    let tree = temp.path().join("modules");
    std::fs::create_dir_all(tree.join("kernel/lib")).unwrap();
    std::fs::write(
        tree.join("modules.dep"),
        "kernel/foo_bar.ko: kernel/lib/helper.ko\nkernel/lib/helper.ko:\nkernel/unselected.ko:\n",
    )
    .unwrap();
    std::fs::write(tree.join("modules.builtin"), "kernel/builtin.ko\n").unwrap();
    std::fs::write(tree.join("kernel/foo_bar.ko"), b"selected module bytes").unwrap();
    std::fs::write(
        tree.join("kernel/lib/helper.ko"),
        b"dependency module bytes",
    )
    .unwrap();
    std::fs::write(tree.join("kernel/unselected.ko"), b"must not be packed").unwrap();
    let init = temp.path().join("init");
    let elf = static_elf();
    std::fs::write(&init, &elf).unwrap();
    let config = temp.path().join("config");
    // Synthetic module bytes test packaging, not a runnable driver/kernel ABI.
    let mut module_config = std::fs::read_to_string(base_config)
        .unwrap()
        .lines()
        .filter(|line| {
            !line.starts_with("CONFIG_MODULES=") && *line != "# CONFIG_MODULES is not set"
        })
        .collect::<Vec<_>>()
        .join("\n");
    module_config.push_str("\nCONFIG_MODULES=y\n");
    std::fs::write(&config, &module_config).unwrap();
    let out = temp.path().join("image.pmi");
    let result = build(
        kernel,
        &config,
        &init,
        &tree,
        &out,
        &["foo-bar", "foo_bar", "builtin"],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let diagnostics = String::from_utf8_lossy(&result.stderr);
    for expected in [
        "arma: selected module: kernel/foo_bar.ko",
        "arma: dependency module: kernel/lib/helper.ko",
        "arma: built-in module: builtin",
    ] {
        assert!(
            diagnostics.lines().any(|line| line == expected),
            "{diagnostics}"
        );
    }
    let bytes = std::fs::read(&out).unwrap();
    let pe = goblin::pe::PE::parse(&bytes).unwrap();
    let section = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap() == ".initrd")
        .unwrap();
    let dtb = common::base_dtb(&bytes);
    let dt: Tree<'_> = Tree::parse(&dtb).unwrap();
    let chosen = dt.find_path("/chosen").unwrap();
    let start_prop = chosen.property("linux,initrd-start").unwrap();
    let end_prop = chosen.property("linux,initrd-end").unwrap();
    let extent = u64::from_be_bytes(end_prop.as_ref().try_into().unwrap())
        - u64::from_be_bytes(start_prop.as_ref().try_into().unwrap());
    let offset = section.pointer_to_raw_data as usize;
    let archive = &bytes[offset..offset + usize::try_from(extent).unwrap()];
    let packed = entries(archive);
    assert_eq!(packed["init"], elf);
    let selected: Vec<_> = packed
        .iter()
        .filter(|(p, _)| Path::new(p).extension().is_some_and(|ext| ext == "ko"))
        .collect();
    assert_eq!(selected.len(), 2);
    assert!(
        selected
            .iter()
            .all(|(p, _)| p.starts_with("usr/lib/modules/"))
    );
    assert!(selected.iter().any(
        |(p, b)| p.ends_with("/kernel/foo_bar.ko") && b.as_slice() == b"selected module bytes"
    ));
    assert!(
        selected
            .iter()
            .any(|(p, b)| p.ends_with("/kernel/lib/helper.ko")
                && b.as_slice() == b"dependency module bytes")
    );
    assert!(
        packed
            .keys()
            .all(|p| !p.ends_with("modules.dep") && !p.ends_with("modules.builtin"))
    );
    let again = build(kernel, &config, &init, &tree, &out, &["builtin", "foo_bar"]);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(bytes, std::fs::read(&out).unwrap());

    let bad = build(
        kernel,
        &config,
        &init,
        &tree,
        &temp.path().join("bad.pmi"),
        &["unknown"],
    );
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("unknown"));
    assert!(!temp.path().join("bad.pmi").exists());

    std::fs::write(
        &config,
        module_config.replace("CONFIG_MODULES=y", "# CONFIG_MODULES is not set"),
    )
    .unwrap();
    let bad = build(
        kernel,
        &config,
        &init,
        &tree,
        &temp.path().join("unsupported.pmi"),
        &["foo_bar"],
    );
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("CONFIG_MODULES"));
    assert!(!temp.path().join("unsupported.pmi").exists());
    std::fs::write(&config, &module_config).unwrap();

    std::fs::write(&init, include_bytes!("data/initramfs.cpio")).unwrap();
    let bad = build(
        kernel,
        &config,
        &init,
        &tree,
        &temp.path().join("archive.pmi"),
        &["foo_bar"],
    );
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("static ELF"));
    assert!(!temp.path().join("archive.pmi").exists());
}

#[test]
fn compressed_modules_follow_kernel_support_in_the_packed_archive() {
    let (kernel, base_config) = common::host_kernel().expect("real kernel and config available");
    let temp = TempDir::new().unwrap();
    let tree = temp.path().join("modules");
    std::fs::create_dir_all(tree.join("kernel/lib")).unwrap();
    std::fs::write(tree.join("modules.builtin"), "").unwrap();
    let init = temp.path().join("init");
    std::fs::write(&init, static_elf()).unwrap();
    let config = temp.path().join("config");
    let base_config = std::fs::read_to_string(base_config)
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("CONFIG_MODULE"))
        .collect::<Vec<_>>()
        .join("\n");
    let out = temp.path().join("image.pmi");
    for (suffix, symbol, compressed) in [
        ("gz", "GZIP", include_bytes!("data/module.ko.gz").as_slice()),
        ("xz", "XZ", include_bytes!("data/module.ko.xz").as_slice()),
        (
            "zst",
            "ZSTD",
            include_bytes!("data/module.ko.zst").as_slice(),
        ),
    ] {
        let root = format!("kernel/root.ko.{suffix}");
        let dependency = format!("kernel/lib/helper.ko.{suffix}");
        std::fs::write(tree.join(&root), compressed).unwrap();
        std::fs::write(tree.join(&dependency), compressed).unwrap();
        let mut index = format!("{root}: {dependency}\n{dependency}:\n");
        // All unselected formats are deliberately invalid compressed streams.
        // They must not trigger codec checks or host decompression.
        for unselected in ["gz", "xz", "zst"] {
            let path = format!("kernel/unselected_{unselected}.ko.{unselected}");
            std::fs::write(tree.join(&path), b"invalid compressed module").unwrap();
            index.push_str(&path);
            index.push_str(":\n");
        }
        std::fs::write(tree.join("modules.dep"), &index).unwrap();
        for keep in [false, true] {
            std::fs::write(
                &config,
                format!(
                    "{base_config}\nCONFIG_MODULES=y\nCONFIG_MODULE_DECOMPRESS={}\nCONFIG_MODULE_COMPRESS_{symbol}=y\n",
                    if keep { "y" } else { "n" }
                ),
            )
            .unwrap();
            let result = build(kernel, &config, &init, &tree, &out, &["root"]);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let image = std::fs::read(&out).unwrap();
            let pe = goblin::pe::PE::parse(&image).unwrap();
            let section = pe
                .sections
                .iter()
                .find(|s| s.name().unwrap() == ".initrd")
                .unwrap();
            let packed = entries(&image[section.pointer_to_raw_data as usize..]);
            let module_files: Vec<_> = packed
                .iter()
                .filter(|(path, _)| path.starts_with("usr/lib/modules/") && path.contains(".ko"))
                .collect();
            assert_eq!(module_files.len(), 2);
            for (path, bytes) in module_files {
                let expected = if keep {
                    compressed
                } else {
                    b"\0module payload\xff\n"
                };
                assert_eq!(bytes, expected);
                assert!(
                    if keep {
                        path.ends_with(&root) || path.ends_with(&dependency)
                    } else {
                        path.ends_with("/kernel/root.ko") || path.ends_with("/kernel/lib/helper.ko")
                    },
                    "{path}"
                );
            }
            assert!(
                !packed
                    .keys()
                    .any(|path| path.contains("unselected") || path.ends_with("modules.dep"))
            );
            let again = build(kernel, &config, &init, &tree, &out, &["root", "root"]);
            assert!(again.status.success());
            assert_eq!(image, std::fs::read(&out).unwrap());
        }
        // The read-only source tree and its index must not be rewritten.
        assert_eq!(
            std::fs::read_to_string(tree.join("modules.dep")).unwrap(),
            index
        );
        assert_eq!(std::fs::read(tree.join(root)).unwrap(), compressed);
        assert_eq!(std::fs::read(tree.join(dependency)).unwrap(), compressed);
    }
}

#[test]
fn module_cli_rejects_incompatible_and_invalid_options_before_reading_inputs() {
    for options in [vec!["--module-tree", "missing"], vec!["--module", "valid"]] {
        let result = Command::new(common::arma_bin())
            .args(["build", "--kernel", "missing", "--cmdline", "ro"])
            .args(options)
            .arg("missing.pmi")
            .output()
            .unwrap();
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!stderr.contains("read kernel"), "{stderr}");
    }
    for name in [
        "../foo", "foo.ko", "foo bar", "foo=1", "foo*", "é", "foo\n", "-foo", "",
    ] {
        let result = Command::new(common::arma_bin())
            .args([
                "build",
                "--kernel",
                "missing",
                "--initrd",
                "missing",
                "--cmdline",
                "ro",
                "--module",
            ])
            .arg(name)
            .arg("missing.pmi")
            .output()
            .unwrap();
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!stderr.contains("read kernel"), "{stderr}");
    }
}
