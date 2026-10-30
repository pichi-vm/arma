// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Image construction with controlled kernel configurations. Guest boot tests
//! in dillo use stock kernels paired with their published configurations.

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use devtree::{NodeView, PropertyView, Tree, TreeView};
use pmi::vm::{Action, FillKind, Spec, vcpu};
use tempfile::TempDir;

#[cfg(target_arch = "x86_64")]
type CpuState = vcpu::x86_64::CpuState;
#[cfg(target_arch = "aarch64")]
type CpuState = vcpu::aarch64::CpuState;

const GRAN: u32 = 2 * 1024 * 1024;
const SUPPORT: &str = "CONFIG_BOOT_CONFIG=y\nCONFIG_BLK_DEV_INITRD=y\nCONFIG_PROC_FS=y\n";

struct Fixture {
    dir: TempDir,
    kernel: PathBuf,
    config: String,
}

impl Fixture {
    fn new() -> Self {
        let (kernel, config) = common::host_kernel().expect("real host kernel available");
        let config = std::fs::read_to_string(config).unwrap();
        let config = config
            .lines()
            .filter(|line| {
                ![
                    "CONFIG_BOOT_CONFIG",
                    "CONFIG_BLK_DEV_INITRD=",
                    "CONFIG_PROC_FS=",
                    "CONFIG_CMDLINE",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            })
            .collect::<Vec<_>>()
            .join("\n");
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("initrd"),
            include_bytes!("data/initramfs.cpio"),
        )
        .unwrap();
        Self {
            dir,
            kernel: kernel.to_owned(),
            config,
        }
    }

    fn image(&self) -> PathBuf {
        self.dir.path().join("image.pmi")
    }

    fn build(&self, cmdline: &str, options: &str, initrd: bool, serial: bool) -> Output {
        let config = self.dir.path().join("kernel.config");
        std::fs::write(&config, format!("{}\n{options}\n", self.config)).unwrap();
        if self.image().exists() {
            std::fs::remove_file(self.image()).unwrap();
        }
        let mut command = Command::new(common::arma_bin());
        command
            .arg("build")
            .arg("--kernel")
            .arg(&self.kernel)
            .arg("--config")
            .arg(config)
            .arg("--cmdline")
            .arg(cmdline);
        if initrd {
            command.arg("--initrd").arg(self.dir.path().join("initrd"));
        }
        if serial {
            command.arg("--serial");
        }
        command.arg(self.image()).output().unwrap()
    }

    fn assert_layout(&self, cmdline: &str, enabled: bool) {
        let bytes = std::fs::read(self.image()).unwrap();
        let pe = goblin::pe::PE::parse(&bytes).unwrap();
        let archive = pe
            .sections
            .iter()
            .find(|s| s.name().unwrap() == ".initrd")
            .unwrap();
        assert_eq!(archive.virtual_address % GRAN, 0);
        assert_eq!(archive.virtual_size % GRAN, 0);
        let fills: Vec<_> = pe
            .sections
            .iter()
            .filter(|s| s.name().unwrap() == ".bconf")
            .collect();
        assert_eq!(fills.len(), usize::from(enabled));
        let mut end = archive.virtual_address + archive.virtual_size;
        if let Some(fill) = fills.first() {
            assert_eq!(fill.virtual_address, end);
            assert_eq!(fill.virtual_address % GRAN, 0);
            assert_eq!(fill.virtual_size, GRAN);
            assert_eq!(fill.size_of_raw_data, 0);
            assert_eq!(fill.pointer_to_raw_data, 0);
            end += GRAN;
        }
        let (offset, len) = common::find_pmi_vm(&bytes);
        let spec: Spec<CpuState> = ciborium::from_reader(&bytes[offset..offset + len]).unwrap();
        let actions: Vec<_> = spec
            .actions
            .iter()
            .enumerate()
            .filter_map(|(i, action)| match action {
                Action::Fill(fill) if fill.kind == FillKind::LbcBootconfig => Some((i, fill)),
                _ => None,
            })
            .collect();
        assert_eq!(actions.len(), usize::from(enabled));
        if let Some(&(index, fill)) = actions.first() {
            assert_eq!(fill.section, ".bconf");
            assert_eq!(
                fill.gpa,
                u64::from(archive.virtual_address + archive.virtual_size)
            );
            assert!(matches!(&spec.actions[index - 1], Action::Load(load)
                if load.section == ".initrd" && load.gpa == u64::from(archive.virtual_address)));
        }
        let dtb = common::base_dtb(&bytes);
        let tree: Tree<'_> = Tree::parse(&dtb).unwrap();
        let chosen = tree.find_path("/chosen").unwrap();
        assert_eq!(chosen.property("bootargs").unwrap().as_str(), Some(cmdline));
        assert_eq!(
            chosen.property("linux,initrd-start").unwrap().as_u64(),
            Some(u64::from(archive.virtual_address))
        );
        assert_eq!(
            chosen.property("linux,initrd-end").unwrap().as_u64(),
            Some(u64::from(end))
        );
    }
}

#[test]
fn command_line_selects_bootconfig_layout() {
    let fixture = Fixture::new();
    for (cmdline, enabled) in [
        ("console=hvc0 bootconfig -- init-argument", true),
        ("bootconfig=0 console=hvc0", true),
        ("\"bootconfig\" console=hvc0", true),
        ("bootconfig bootconfig", true),
        ("console=hvc0", false),
        ("console=hvc0 -- bootconfig", false),
        ("label=\"a bootconfig b\"", false),
    ] {
        let output = fixture.build(cmdline, SUPPORT, true, false);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture.assert_layout(cmdline, enabled);
    }
    let output = fixture.build("bootconfig console=hvc0", SUPPORT, true, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_layout("earlycon bootconfig console=hvc0", true);
}

#[test]
fn rejected_bootconfig_builds_leave_no_image() {
    let fixture = Fixture::new();
    for option in [
        "CONFIG_BOOT_CONFIG",
        "CONFIG_BLK_DEV_INITRD",
        "CONFIG_PROC_FS",
    ] {
        let config = SUPPORT.replace(&format!("{option}=y"), &format!("{option}=n"));
        let output = fixture.build("bootconfig", &config, true, false);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(&format!("{option}=y")));
        assert!(!fixture.image().exists());
    }
    let output = fixture.build("bootconfig", SUPPORT, false, false);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nonempty --initrd"));
    assert!(!fixture.image().exists());

    let config = format!(
        "{SUPPORT}CONFIG_CMDLINE_BOOL=y\nCONFIG_CMDLINE_OVERRIDE=y\nCONFIG_CMDLINE_FORCE=y\nCONFIG_CMDLINE=\"quiet\"\n"
    );
    let output = fixture.build("bootconfig", &config, true, false);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("removes bootconfig activation"));
    assert!(!fixture.image().exists());
    let forced = format!("{config}CONFIG_BOOT_CONFIG_FORCE=y\n");
    let output = fixture.build("bootconfig", &forced, true, false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_layout("bootconfig", true);

    std::fs::write(fixture.dir.path().join("initrd"), []).unwrap();
    let output = fixture.build("bootconfig", SUPPORT, true, false);
    assert!(!output.status.success());
    assert!(!fixture.image().exists());
}

#[test]
fn kernel_defaults_do_not_request_a_reservation() {
    let fixture = Fixture::new();
    for config in [
        "CONFIG_BOOT_CONFIG=n\nCONFIG_BLK_DEV_INITRD=y\nCONFIG_PROC_FS=n\n".to_owned(),
        format!(
            "{SUPPORT}CONFIG_BOOT_CONFIG_FORCE=y\nCONFIG_CMDLINE=\"bootconfig\"\nCONFIG_CMDLINE_BOOL=y\nCONFIG_CMDLINE_FORCE=y\n"
        ),
    ] {
        let output = fixture.build("console=hvc0", &config, true, false);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture.assert_layout("console=hvc0", false);
    }
}
