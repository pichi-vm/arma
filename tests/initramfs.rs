// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exercise complete archives through the CLI and inspect the emitted PMI.
mod common;

use std::process::Command;

use devtree::{NodeView, PropertyView, Tree, TreeView};
use pmi::vm::{Action, FillKind, Spec, vcpu};
use rstest::rstest;
use tempfile::TempDir;

#[cfg(target_arch = "x86_64")]
type CpuState = vcpu::x86_64::CpuState;
#[cfg(target_arch = "aarch64")]
type CpuState = vcpu::aarch64::CpuState;

const GRAN: u64 = 2 * 1024 * 1024;

#[rstest]
#[case(include_bytes!("data/initramfs.cpio").as_slice())]
#[case(include_bytes!("data/initramfs.cpio.gz").as_slice())]
#[case(include_bytes!("data/initramfs.cpio.zst").as_slice())]
fn complete_initramfs_reaches_pmi_unchanged(#[case] archive: &[u8]) {
    let (kernel, config) = common::host_kernel().expect("real host kernel and config available");
    let dir = TempDir::new().unwrap();
    let initrd = dir.path().join("initramfs");
    let output = dir.path().join("boot.pmi");
    std::fs::write(&initrd, archive).unwrap();
    let build = || {
        Command::new(common::arma_bin())
            .arg("build")
            .arg("--kernel")
            .arg(kernel)
            .arg("--config")
            .arg(config)
            .arg("--cmdline")
            .arg("console=hvc0 -- init-argument")
            .arg("--initrd")
            .arg(&initrd)
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = build();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(&output).unwrap();
    let pe = goblin::pe::PE::parse(&bytes).unwrap();
    let section = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap() == ".initrd")
        .unwrap();
    let start = section.pointer_to_raw_data as usize;
    assert_eq!(&bytes[start..start + archive.len()], archive);
    // The rest of the loaded section is padding, not a second transformed copy.
    assert!(
        bytes[start + archive.len()..start + section.size_of_raw_data as usize]
            .iter()
            .all(|b| *b == 0)
    );
    assert_eq!(u64::from(section.virtual_address) % GRAN, 0);
    assert_eq!(u64::from(section.pointer_to_raw_data) % GRAN, 0);
    assert_eq!(
        u64::from(section.virtual_size),
        (archive.len() as u64).div_ceil(GRAN) * GRAN
    );
    assert!(!pe.sections.iter().any(|s| s.name().unwrap() == ".bconf"));
    let (off, len) = common::find_pmi_vm(&bytes);
    let spec: Spec<CpuState> = ciborium::from_reader(&bytes[off..off + len]).unwrap();
    assert!(!spec.actions.iter().any(|action| matches!(action,
        Action::Fill(fill) if fill.kind == FillKind::LbcBootconfig
    )));
    let dtb = common::base_dtb(&bytes);
    let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
    let chosen = tree.find_path("/chosen").unwrap();
    let start_prop = chosen.property("linux,initrd-start").unwrap();
    let end_prop = chosen.property("linux,initrd-end").unwrap();
    let start_gpa = u64::from_be_bytes(start_prop.as_ref().try_into().unwrap());
    let end_gpa = u64::from_be_bytes(end_prop.as_ref().try_into().unwrap());
    assert_eq!(start_gpa, u64::from(section.virtual_address));
    assert_eq!(
        end_gpa,
        u64::from(section.virtual_address) + u64::from(section.virtual_size)
    );
    assert_eq!(
        chosen.property("bootargs").unwrap().as_str(),
        Some("console=hvc0 -- init-argument")
    );

    std::fs::remove_file(&output).unwrap();
    std::fs::write(&initrd, &archive[..archive.len() / 2]).unwrap();
    let result = build();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("materialize initrd"));
    assert!(!output.exists());
}
