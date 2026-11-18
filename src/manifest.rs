// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PMI CBOR manifest construction.
//!
//! Builds a `pmi::vm::Spec<P>` with an architecture-specific CPU profile
//! and the ordered actions for arma's chosen layout. PMI defines the
//! initial CPU state; the image carries no register map.

use anyhow::Result;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use pmi::vm::{Action, Fill, FillKind, Load, LoadKind, Spec};

#[cfg(target_arch = "aarch64")]
use pmi::aarch64::Profile;
#[cfg(target_arch = "x86_64")]
use pmi::x86_64::Profile;

use crate::tatu::TatuImage;

/// Names assigned to arma's own PE sections (tatu's `.tatu.*` names
/// come straight from tatu's ELF).
pub(crate) const SECTION_LINUX: &str = ".linux";
pub(crate) const SECTION_INITRD: &str = ".initrd";
pub(crate) const SECTION_BOOTCONFIG: &str = ".bconf";
/// x86 KASLR relocation table (loaded for tatu to consume at boot).
pub(crate) const SECTION_RELOCS: &str = ".linux.relocs";
// The base DTB and host-DTBO are tatu-defined sections (arma fills
// `.tatu.dtb`, dillo fills `.tatu.dtbo`).
pub(crate) const SECTION_DTB: &str = ".tatu.dtb";
pub(crate) const SECTION_DTBO: &str = ".tatu.dtbo";
/// Bundled fallback base DTB for optional mode: carried in the PE and named by
/// the [`dt:dtb`](../../pmi/spec/dt.md) attribute, but placed nowhere in guest
/// memory. The `dt:dtb` fill target (`.tatu.dtb`) receives the launch base at
/// runtime, from an out-of-band source or from this fallback.
pub(crate) const SECTION_DTB_FALLBACK: &str = ".dtb";

/// How the base DTB is delivered to the guest (`dt` extension channel modes,
/// `pmi/spec/dt.md`). arma emits the `dt:dtb` attribute and the base action per
/// the selected mode.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum DtbMode {
    /// Bundled: the base travels in `.tatu.dtb` and reaches guest memory by a
    /// `default` load; the `dt:dtb` attribute names it. No `dt:dtb` fill.
    Attached,

    /// Detached: the base is delivered out-of-band and written by a `dt:dtb`
    /// fill into the reserved `.tatu.dtb` Zero section; no `dt:dtb` attribute.
    Detached,

    /// Optional (default): a `dt:dtb` fill delivers the launch base into
    /// `.tatu.dtb`, and the `dt:dtb` attribute names the bundled fallback
    /// (`.dtb`) the VMM uses when it has no out-of-band base.
    Optional,
}

impl DtbMode {
    /// The `dt:dtb` target attribute for this mode: the PE section holding the
    /// bundled base, or `None` in detached mode (no bundled base).
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn attribute(self) -> Option<String> {
        match self {
            DtbMode::Attached => Some(SECTION_DTB.into()),
            DtbMode::Optional => Some(SECTION_DTB_FALLBACK.into()),
            DtbMode::Detached => None,
        }
    }
}
/// `IMAGE_SCN_MEM_DISCARDABLE` per the PMI spec for the non-loaded
/// target spec section.
pub(crate) const SECTION_PMI_VM: &str = ".pmi.vm";

/// The guest-physical addresses each `load`/`fill` action places its section
/// at. Per `pmi/spec/granularity.md` (commit `f6be1eb`) every action carries an
/// explicit `gpa`; the VMM places bytes there verbatim and never consults the
/// PE `VirtualAddress`. arma's placement and PE `VirtualAddress` happen to
/// coincide, but the manifest now states the GPA outright. Tatu sections and
/// the `.tatu.dtbo` fill target are linked at absolute addresses (their GPA is
/// the ELF `vaddr`); the kernel/initrd/relocs GPAs come from the planner.
#[derive(Copy, Clone)]
pub(crate) struct ActionGpas {
    pub(crate) linux: u64,
    pub(crate) initrd: Option<u64>,
    pub(crate) bootconfig: Option<u64>,
    pub(crate) relocs: Option<u64>,
}

/// Build the native `.pmi.vm` manifest from firmware sections and placement.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn build_pmi_vm(
    tatu: &TatuImage,
    gpas: ActionGpas,
    cpu_profile: Option<&str>,
    dtb_mode: DtbMode,
) -> Result<Vec<u8>> {
    use anyhow::Context;
    use ciborium::ser::into_writer;
    use pmi::Version;
    use serde::{
        Deserialize,
        de::value::{Error as ValueError, StrDeserializer},
    };

    let cpu_profile = cpu_profile
        .map(|profile| {
            Profile::deserialize(StrDeserializer::<ValueError>::new(profile))
                .with_context(|| format!("invalid native CPU profile {profile:?}"))
        })
        .transpose()?
        .unwrap_or_default();
    let spec = Spec {
        version: Version::default(),
        actions: build_actions(tatu, gpas, dtb_mode),
        cpu_profile,
        dt_dtb: dtb_mode.attribute(),
    };
    let mut buf = Vec::new();
    into_writer(&spec, &mut buf).context("CBOR encode of .pmi.vm spec")?;
    Ok(buf)
}

// Other hosts can inspect images; native_tatu_elf rejects their build path
// before manifest construction because no firmware artifact is available.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn build_pmi_vm(
    _tatu: &TatuImage,
    _gpas: ActionGpas,
    _cpu_profile: Option<&str>,
    _dtb_mode: DtbMode,
) -> Result<Vec<u8>> {
    anyhow::bail!("native PMI generation requires an x86_64 or aarch64 host")
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn build_actions(tatu: &TatuImage, gpas: ActionGpas, dtb_mode: DtbMode) -> Vec<Action> {
    let mut out = Vec::with_capacity(16);

    // Tatu sections — one load per SHF_ALLOC section, in vaddr order
    // (already sorted by parse()). Two exceptions never load: `.tatu.dtbo`
    // is the unmeasured host-DTBO fill target, and `.tatu.dtb` is the base
    // DTB fill target in detached/optional mode (a `dt:dtb` fill delivers
    // it; see below). In attached mode `.tatu.dtb` loads like the rest. The
    // x86 boot CPU tables `.tatu.pgt` / `.tatu.gdt` (const-fn-baked by tatu)
    // always load. Each tatu section is linked at an absolute address, so
    // its `vaddr` is the explicit action GPA.
    for s in &tatu.sections {
        if s.name == SECTION_DTBO {
            continue;
        }
        if s.name == SECTION_DTB && dtb_mode != DtbMode::Attached {
            continue;
        }
        out.push(Action::Load(Load {
            gpa: s.vaddr,
            section: s.name.clone(),
            kind: LoadKind::default(),
        }));
    }

    // Kernel, then optional initrd / relocs, at their planner-assigned GPAs.
    // The base DTB (`.tatu.dtb`) is loaded by the tatu-sections loop above.
    out.push(Action::Load(Load {
        gpa: gpas.linux,
        section: SECTION_LINUX.into(),
        kind: LoadKind::default(),
    }));
    if let Some(gpa) = gpas.initrd {
        out.push(Action::Load(Load {
            gpa,
            section: SECTION_INITRD.into(),
            kind: LoadKind::default(),
        }));
    }
    if let Some(gpa) = gpas.bootconfig {
        out.push(Action::Fill(Fill {
            gpa,
            section: SECTION_BOOTCONFIG.into(),
            kind: FillKind::LbcBootconfig,
        }));
    }
    if let Some(gpa) = gpas.relocs {
        out.push(Action::Load(Load {
            gpa,
            section: SECTION_RELOCS.into(),
            kind: LoadKind::default(),
        }));
    }

    // Base DTB fill (detached/optional) — the VMM delivers the measured base
    // into the reserved `.tatu.dtb` Zero section, from an out-of-band source or
    // (optional) the bundled `.dtb` fallback. Attached mode loads the base
    // instead (above) and has no `dt:dtb` fill.
    if dtb_mode != DtbMode::Attached {
        let dtb_gpa = tatu.section(SECTION_DTB).map_or(0, |s| s.vaddr);
        out.push(Action::Fill(Fill {
            gpa: dtb_gpa,
            section: SECTION_DTB.into(),
            kind: FillKind::DtDtb,
        }));
    }

    // Host-DTBO fill — the unmeasured half of the dt extension. Its fill
    // target is the tatu-defined `.tatu.dtbo` section, placed at its ELF vaddr.
    let dtbo_gpa = tatu.section(SECTION_DTBO).map_or(0, |s| s.vaddr);
    out.push(Action::Fill(Fill {
        gpa: dtbo_gpa,
        section: SECTION_DTBO.into(),
        kind: FillKind::DtDtbo,
    }));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::Arch;
    use crate::tatu::parse as parse_tatu;
    use ciborium::de::from_reader;

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn rejects_invalid_native_profiles() {
        #[cfg(target_arch = "x86_64")]
        let (firmware, arch, invalid) =
            (crate::TATU_X86_64, Arch::X86_64, ["armv8.0-a", "x86-64-v5"]);
        #[cfg(target_arch = "aarch64")]
        let (firmware, arch, invalid) = (
            crate::TATU_AARCH64,
            Arch::Aarch64,
            ["x86-64-v1", "armv9.9-a"],
        );
        let tatu = parse_tatu(firmware, arch).unwrap();
        let gpas = ActionGpas {
            linux: 0x20_0000,
            initrd: None,
            bootconfig: None,
            relocs: None,
        };
        for profile in invalid {
            assert!(
                build_pmi_vm(&tatu, gpas, Some(profile), DtbMode::Attached).is_err(),
                "{profile}"
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn x86_manifest_round_trips_via_strict_decoder() {
        use crate::TATU_X86_64;
        let tatu = parse_tatu(TATU_X86_64, Arch::X86_64).unwrap();
        let gpas = ActionGpas {
            linux: 0x20_0000,
            initrd: Some(0x100_0000),
            bootconfig: Some(0x120_0000),
            relocs: Some(0x200_0000),
        };
        let cbor = build_pmi_vm(&tatu, gpas, Some("x86-64-v3"), DtbMode::Attached).unwrap();
        let decoded: Spec<pmi::x86_64::Profile> =
            from_reader(cbor.as_slice()).expect("strict round-trip decode");
        assert_eq!(decoded.cpu_profile, pmi::x86_64::Profile::V3);
        // The kernel load carries its explicit planner GPA.
        let linux_gpa = decoded.actions.iter().find_map(|a| match a {
            Action::Load(l) if l.section == SECTION_LINUX => Some(l.gpa),
            _ => None,
        });
        assert_eq!(linux_gpa, Some(0x20_0000));
        assert!(matches!(decoded.dt_dtb, Some(s) if s == ".tatu.dtb"));
        // Last action must be the fill for .dtbo.
        let last = decoded.actions.last().unwrap();
        match last {
            Action::Fill(f) => {
                assert_eq!(f.section, SECTION_DTBO);
                assert!(matches!(f.kind, pmi::vm::FillKind::DtDtbo));
            }
            Action::Load(_) => panic!("last action must be Fill"),
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn aarch64_manifest_uses_typed_profile() {
        use crate::TATU_AARCH64;
        let tatu = parse_tatu(TATU_AARCH64, Arch::Aarch64).unwrap();
        let gpas = ActionGpas {
            linux: 0x20_0000,
            initrd: None,
            bootconfig: None,
            relocs: None,
        };
        let cbor = build_pmi_vm(&tatu, gpas, Some("armv8.2-a"), DtbMode::Optional).unwrap();
        let decoded: Spec<pmi::aarch64::Profile> =
            from_reader(cbor.as_slice()).expect("strict round-trip decode");
        assert_eq!(decoded.cpu_profile, pmi::aarch64::Profile::V8_2);
    }

    #[cfg(target_arch = "x86_64")]
    fn actions_of(mode: DtbMode) -> (Option<String>, Vec<Action>) {
        use crate::TATU_X86_64;
        let tatu = parse_tatu(TATU_X86_64, Arch::X86_64).unwrap();
        let gpas = ActionGpas {
            linux: 0x20_0000,
            initrd: None,
            bootconfig: None,
            relocs: None,
        };
        let cbor = build_pmi_vm(&tatu, gpas, Some("x86-64-v3"), mode).unwrap();
        let decoded: Spec<pmi::x86_64::Profile> = from_reader(cbor.as_slice()).unwrap();
        (decoded.dt_dtb, decoded.actions)
    }

    #[cfg(target_arch = "x86_64")]
    fn base_action(actions: &[Action]) -> Option<(&'static str, Option<FillKind>)> {
        actions.iter().find_map(|a| match a {
            Action::Load(l) if l.section == SECTION_DTB => Some(("load", None)),
            Action::Fill(f) if f.section == SECTION_DTB => Some(("fill", Some(f.kind))),
            _ => None,
        })
    }

    // Each channel mode emits the base-DTB action and `dt:dtb` attribute the
    // dt extension prescribes (pmi/spec/dt.md, VMM selection table).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn attached_loads_base_and_names_it() {
        let (attr, actions) = actions_of(DtbMode::Attached);
        assert_eq!(attr.as_deref(), Some(SECTION_DTB)); // ".tatu.dtb"
        assert_eq!(base_action(&actions), Some(("load", None)));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn optional_fills_base_and_names_fallback() {
        let (attr, actions) = actions_of(DtbMode::Optional);
        assert_eq!(attr.as_deref(), Some(SECTION_DTB_FALLBACK)); // ".dtb"
        assert_eq!(base_action(&actions), Some(("fill", Some(FillKind::DtDtb))));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn detached_fills_base_with_no_attribute() {
        let (attr, actions) = actions_of(DtbMode::Detached);
        assert_eq!(attr, None);
        assert_eq!(base_action(&actions), Some(("fill", Some(FillKind::DtDtb))));
    }
}
