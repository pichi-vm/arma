// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `arma check <pmi>` — read-only guest-physical layout linter (C6,
//! device-model §6). Renders the full map (device island, payload, the PCIe
//! BAR window + its burned buddy) and flags fragmentation, alignment, and the
//! window invariants. Changes nothing. A clean `check` is part of what "sane
//! output" means.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use ciborium::value::Value;
use devtree::{NodeView, Tree, TreeView};

const MIB: u64 = 1024 * 1024;
const TWO_MIB: u64 = 2 * MIB;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Device,
    Window,
    Burned,
    Payload,
}

struct Region {
    name: String,
    base: u64,
    size: u64,
    kind: Kind,
}

// Layout inspection uses only these fields; other launch attributes, including
// legacy CPU state, deliberately remain outside this checker's contract.
struct Manifest {
    actions: Vec<Action>,
    dt_dtb: Option<String>,
}

// Load/fill kinds select boot-time content, not the destination's extent.
struct Action {
    section: String,
    gpa: u64,
}

impl Manifest {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Value = ciborium::from_reader(bytes).context("decode .pmi.vm CBOR")?;
        let Value::Map(fields) = value else {
            bail!(".pmi.vm must be a map");
        };
        let mut actions = None;
        let mut dt_dtb = None;
        for (key, value) in fields {
            match key.as_text() {
                Some("actions") => {
                    ensure!(actions.is_none(), "duplicate actions field");
                    let Value::Array(values) = value else {
                        bail!("actions must be an array");
                    };
                    actions = Some(
                        values
                            .into_iter()
                            .map(Action::parse)
                            .collect::<Result<_>>()?,
                    );
                }
                Some("dt:dtb") => {
                    ensure!(dt_dtb.is_none(), "duplicate dt:dtb field");
                    let Value::Text(name) = value else {
                        bail!("dt:dtb must be a text string");
                    };
                    dt_dtb = Some(name);
                }
                _ => {}
            }
        }
        Ok(Self {
            actions: actions.context("missing actions field")?,
            dt_dtb,
        })
    }
}

impl Action {
    fn parse(value: Value) -> Result<Self> {
        let Value::Map(fields) = value else {
            bail!("action must be a map");
        };
        let mut kind = None;
        let mut section = None;
        let mut gpa = None;
        for (key, value) in fields {
            match key.as_text() {
                Some("type") => {
                    ensure!(kind.is_none(), "duplicate action type field");
                    let Value::Text(name) = value else {
                        bail!("action type must be a text string");
                    };
                    kind = Some(name);
                }
                Some("section") => {
                    ensure!(section.is_none(), "duplicate action section field");
                    let Value::Text(name) = value else {
                        bail!("action section must be a text string");
                    };
                    section = Some(name);
                }
                Some("gpa") => {
                    ensure!(gpa.is_none(), "duplicate action gpa field");
                    let Value::Integer(integer) = value else {
                        bail!("action gpa must be an unsigned 64-bit integer");
                    };
                    gpa = Some(u64::try_from(integer).context("action gpa is outside u64 range")?);
                }
                _ => {}
            }
        }
        let section = section.context("missing action section field")?;
        let gpa = gpa.context("missing action gpa field")?;
        match kind.context("missing action type field")?.as_str() {
            "load" | "fill" => Ok(Self { section, gpa }),
            other => bail!("unknown action type {other:?}"),
        }
    }
}

pub(crate) fn run(pmi_path: &Path) -> Result<()> {
    let bytes =
        std::fs::read(pmi_path).with_context(|| format!("read PMI: {}", pmi_path.display()))?;
    let pe = goblin::pe::PE::parse(&bytes).context("parse PMI as PE")?;

    let cbor =
        section_raw(&bytes, &pe, ".pmi.vm").context(".pmi.vm section absent from the PMI")?;
    let manifest = Manifest::parse(cbor)?;

    let mut regions: Vec<Region> = Vec::new();
    for action in manifest.actions {
        let Action { section: name, gpa } = action;
        let section = pe
            .sections
            .iter()
            .find(|s| s.name().unwrap_or("").trim_end_matches('\0') == name)
            .with_context(|| format!("action names section `{name}`, absent from the PMI"))?;
        let size = u64::from(section.virtual_size);
        gpa.checked_add(size)
            .with_context(|| format!("action range for `{name}` overflows"))?;
        regions.push(Region {
            name,
            base: gpa,
            size,
            kind: Kind::Payload,
        });
    }

    // Locate the bundled base DTB through the `dt:dtb` attribute in `.pmi.vm`
    // (`.tatu.dtb` in attached mode, `.dtb` in optional). A detached image
    // carries no attribute and no bundled base, so its device regions cannot be
    // shown here.
    match base_dtb_bytes(&bytes, &pe, manifest.dt_dtb.as_deref())? {
        Some(dtb) => regions.extend(base_device_regions(dtb)?),
        None => println!("(base DTB is detached; device regions omitted)"),
    }

    regions.sort_by_key(|r| r.base);

    // The PCIe BAR window (if any) drives the window/space invariant checks.
    let window: Option<(u64, u64)> = regions
        .iter()
        .find(|r| r.kind == Kind::Window)
        .map(|r| (r.base, r.size));

    // ---- render ----
    println!("arma check: {}", pmi_path.display());
    // Size each column to its widest value so names of any length stay aligned.
    let size_strs: Vec<String> = regions.iter().map(|r| human(r.size)).collect();
    let name_w = regions
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(0)
        .max("region".len());
    let size_w = size_strs
        .iter()
        .map(String::len)
        .max()
        .unwrap_or(0)
        .max("size".len());
    let addr_w = 14; // "0x" + up to 12 hex digits (top of address space is 2^39+)
    println!(
        "  {:<name_w$}  {:>addr_w$}  {:>addr_w$}  {:>size_w$}  kind",
        "region", "start", "end", "size",
    );
    for (r, size_s) in regions.iter().zip(&size_strs) {
        let tag = match r.kind {
            Kind::Device => "device",
            Kind::Window => "BAR window",
            Kind::Burned => "burned",
            Kind::Payload => "payload",
        };
        println!(
            "  {:<name_w$}  {:>#addr_w$x}  {:>#addr_w$x}  {size_s:>size_w$}  {tag}",
            r.name,
            r.base,
            r.base + r.size,
        );
    }

    // ---- checks ----
    let mut problems: Vec<String> = Vec::new();

    // 1. Disjoint (no overlaps).
    for w in regions.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        if a.base + a.size > b.base {
            problems.push(format!(
                "overlap: {} [{:#x}..{:#x}) and {} [{:#x}..{:#x})",
                a.name,
                a.base,
                a.base + a.size,
                b.name,
                b.base,
                b.base + b.size
            ));
        }
    }

    // 2. Window invariants (§6): 2^B-aligned, at [2^X − 2^(B+1), 2^X − 2^B),
    //    nothing emitted above it, all within 2^X.
    if let Some((wb, ws)) = window {
        if !ws.is_power_of_two() {
            problems.push(format!("BAR window size {ws:#x} is not 2^B"));
        } else if wb % ws != 0 {
            problems.push(format!("BAR window base {wb:#x} not 2^B-aligned"));
        }
        let space_top = wb + 2 * ws;
        if !space_top.is_power_of_two() {
            problems.push(format!(
                "window+burned top {space_top:#x} is not 2^X (window not the lower buddy of the top pair)"
            ));
        }
        // Nothing emitted above the window (device/payload all below it).
        for r in &regions {
            if matches!(r.kind, Kind::Window | Kind::Burned) {
                continue;
            }
            if r.base >= wb {
                problems.push(format!(
                    "{} at {:#x} is at/above the BAR window base {:#x}",
                    r.name, r.base, wb
                ));
            }
            if r.base + r.size > space_top {
                problems.push(format!(
                    "{} ends above the declared address space (2^X = {:#x})",
                    r.name, space_top
                ));
            }
        }
    }

    // 3. Device island: outer edges 2 MiB-aligned (so RAM packs around it).
    let dev: Vec<&Region> = regions
        .iter()
        .filter(|r| r.kind == Kind::Device)
        .filter(|r| window.is_none_or(|(wb, _)| r.base < wb))
        .collect();
    if let (Some(lo), Some(hi)) = (
        dev.iter().map(|r| r.base).min(),
        dev.iter().map(|r| r.base + r.size).max(),
    ) {
        // The low edge is a hard RAM↔device boundary and must be 2 MiB-aligned.
        if lo % TWO_MIB != 0 {
            problems.push(format!("device island low edge {lo:#x} not 2 MiB-aligned"));
        }
        // The high edge is where the VMM places RAM; it rounds up to the next
        // 2 MiB boundary, so the effective boundary is aligned as long as no
        // device straddles it (guaranteed — `hi` is the last device end).
        let top = hi.div_ceil(TWO_MIB) * TWO_MIB;
        println!(
            "  device island: [{lo:#x}..{top:#x}) ({} across {} regions; RAM may start at {top:#x})",
            human(top - lo),
            dev.len()
        );
    }

    println!();
    if problems.is_empty() {
        println!("✓ clean — layout is sane");
        Ok(())
    } else {
        for p in &problems {
            eprintln!("✗ {p}");
        }
        bail!("{} layout problem(s) found", problems.len())
    }
}

/// Device MMIO and PCIe-window regions declared by the base DTB.
fn base_device_regions(dtb: &[u8]) -> Result<Vec<Region>> {
    let tree: Tree<'_> = Tree::parse(dtb).context("parse base DTB")?;
    let root = tree.root();
    let mut regions: Vec<Region> = Vec::new();

    // Device MMIO regions: every node's `reg` pairs (GIC dist+redist, v2m,
    // serial, virtio-mmio×N, ECAM). The 64-bit BAR window comes from the PCIe
    // `ranges`, not a `reg`, and is added separately below.
    let mut window: Option<(u64, u64)> = None;
    for child in root.children() {
        let cname = child.name().to_string();
        if let Some(reg) = child.property("reg") {
            let cells = be_cells(reg.as_ref());
            for (i, chunk) in cells.as_chunks::<4>().0.iter().enumerate() {
                let base = (u64::from(chunk[0]) << 32) | u64::from(chunk[1]);
                let size = (u64::from(chunk[2]) << 32) | u64::from(chunk[3]);
                if size == 0 {
                    continue;
                }
                regions.push(Region {
                    name: if i == 0 {
                        cname.clone()
                    } else {
                        format!("{cname}#{i}")
                    },
                    base,
                    size,
                    kind: Kind::Device,
                });
            }
        }
        // PCIe bridge: the 64-bit window from `ranges` (7-cell tuple; cpu base =
        // cells[3..5], size = cells[5..7]).
        if let Some(ranges) = child.property("ranges") {
            let c = be_cells(ranges.as_ref());
            if c.len() >= 7 {
                let base = (u64::from(c[3]) << 32) | u64::from(c[4]);
                let size = (u64::from(c[5]) << 32) | u64::from(c[6]);
                if size > 0 {
                    window = Some((base, size));
                }
            }
        }
    }

    if let Some((wb, ws)) = window {
        regions.push(Region {
            name: "pcie-bar-window".into(),
            base: wb,
            size: ws,
            kind: Kind::Window,
        });
        regions.push(Region {
            name: "(burned buddy)".into(),
            base: wb + ws,
            size: ws,
            kind: Kind::Burned,
        });
    }

    Ok(regions)
}

/// The bundled base DTB named by the `.pmi.vm` `dt:dtb` attribute, or `None` for
/// a detached image (no attribute, no bundled base).
fn base_dtb_bytes<'b>(
    bytes: &'b [u8],
    pe: &goblin::pe::PE<'_>,
    section: Option<&str>,
) -> Result<Option<&'b [u8]>> {
    let Some(section) = section else {
        return Ok(None);
    };
    let raw = section_raw(bytes, pe, section)
        .with_context(|| format!("dt:dtb names section `{section}`, absent from the PMI"))?;
    Ok(Some(raw))
}

/// Raw file bytes of the named PE section.
fn section_raw<'b>(bytes: &'b [u8], pe: &goblin::pe::PE<'_>, name: &str) -> Option<&'b [u8]> {
    let s = pe
        .sections
        .iter()
        .find(|s| s.name().unwrap_or("").trim_end_matches('\0') == name)?;
    let off = s.pointer_to_raw_data as usize;
    let len = s.size_of_raw_data as usize;
    bytes.get(off..off + len)
}

/// Parse a devicetree cell property (big-endian u32s) from its raw bytes.
fn be_cells(bytes: &[u8]) -> Vec<u32> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .collect()
}

fn human(n: u64) -> String {
    if n >= 1024 * MIB && n.is_multiple_of(1024 * MIB) {
        format!("{} GiB", n / (1024 * MIB))
    } else if n >= MIB && n.is_multiple_of(MIB) {
        format!("{} MiB", n / MIB)
    } else if n >= 1024 && n.is_multiple_of(1024) {
        format!("{} KiB", n / 1024)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ciborium::cbor;

    use super::*;
    use crate::pe::{Section, build_pe};

    #[test]
    fn zero_gpa_actions_participate_in_layout_checks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("layout.pmi");
        for (machine, profile, legacy) in [
            (0x8664, "x86-64-v2", false),
            (0xaa64, "armv8.0-a", false),
            (0x8664, "x86-64-v2", true),
            (0xaa64, "armv8.0-a", true),
        ] {
            for (reset_gpa, fill_gpa, overlaps) in
                [(0, 0x1000, false), (0, 0x800, true), (0x800, 0, true)]
            {
                let kind = if legacy { "merged:dtbo" } else { "dt:dtb" };
                let mut value = cbor!({
                    "version" => 1,
                    "cpu:profile" => profile,
                    "actions" => [
                        {"type" => "load", "gpa" => reset_gpa, "section" => ".reset"},
                        {"type" => "fill", "gpa" => fill_gpa, "section" => ".fill", "kind" => kind},
                    ],
                })
                .unwrap();
                if legacy {
                    value
                        .as_map_mut()
                        .unwrap()
                        .push((Value::Text("vm:vcpu".into()), cbor!({"pc" => 0}).unwrap()));
                }
                let mut manifest = Vec::new();
                ciborium::into_writer(&value, &mut manifest).unwrap();
                let sections = [
                    Section {
                        name: ".reset".into(),
                        vaddr: 0,
                        virtual_size: 0x1000,
                        data: Cow::Borrowed(&[0]),
                        characteristics: 0,
                        non_loaded: false,
                    },
                    Section {
                        name: ".fill".into(),
                        // The action, not the PE address, selects the destination.
                        vaddr: 0x4000,
                        virtual_size: 0x1000,
                        data: Cow::Borrowed(&[]),
                        characteristics: 0,
                        non_loaded: false,
                    },
                    Section {
                        name: ".unused".into(),
                        vaddr: 0,
                        virtual_size: 0x1000,
                        data: Cow::Borrowed(&[0]),
                        characteristics: 0,
                        non_loaded: true,
                    },
                    Section {
                        name: ".pmi.vm".into(),
                        vaddr: 0,
                        virtual_size: manifest.len() as u64,
                        data: Cow::Owned(manifest),
                        characteristics: 0,
                        non_loaded: true,
                    },
                ];
                std::fs::write(&path, build_pe(machine, &sections).unwrap()).unwrap();
                let result = run(&path);
                if overlaps {
                    assert_eq!(result.unwrap_err().to_string(), "1 layout problem(s) found");
                } else {
                    result.unwrap();
                }
            }
        }
    }

    #[test]
    fn present_dtb_attribute_requires_text() {
        // Two-entry map: actions = [], dt:dtb = the appended CBOR value.
        let prefix = b"\xa2\x67actions\x80\x66dt:dtb";
        let mut text = prefix.to_vec();
        text.extend_from_slice(b"\x64.dtb");
        let manifest = Manifest::parse(&text).unwrap();
        assert_eq!(manifest.dt_dtb.as_deref(), Some(".dtb"));

        // CBOR null, undefined, and a URI-tagged string are not text values.
        for non_text in [b"\xf6".as_slice(), b"\xf7", b"\xd8\x20\x64.dtb"] {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(non_text);
            assert!(Manifest::parse(&bytes).is_err());
        }
    }

    #[test]
    fn actions_require_an_actual_array() {
        let prefix = b"\xa1\x67actions";
        for container in [
            b"\x40".as_slice(), // Empty byte string.
            b"\x5f\xff",        // Indefinite empty byte string.
            b"\xa0",            // Empty map.
            b"\xd8\x20\x80",    // Tagged array.
        ] {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(container);
            assert!(Manifest::parse(&bytes).is_err());
        }
        let manifest = Manifest::parse(b"\xa1\x67actions\x80").unwrap();
        assert!(manifest.actions.is_empty());
        assert!(manifest.dt_dtb.is_none());
    }

    #[test]
    fn indefinite_text_keys_and_values_describe_the_same_layout() {
        // Indefinite maps/array with chunked text for every consumed key and
        // text value: actions = [{type: load, section: .reset, gpa: 0}], dt:dtb = .dtb.
        let bytes = b"\xbf\x7f\x63act\x64ions\xff\x9f\xbf\x7f\x62ty\x62pe\xff\x7f\x62lo\x62ad\xff\x7f\x63sec\x64tion\xff\x7f\x62.r\x64eset\xff\x7f\x61g\x62pa\xff\x00\xff\xff\x7f\x63dt:\x63dtb\xff\x7f\x62.d\x62tb\xff\xff";
        let manifest = Manifest::parse(bytes).unwrap();
        assert_eq!(manifest.dt_dtb.as_deref(), Some(".dtb"));
        assert!(
            matches!(manifest.actions.as_slice(), [Action { section, gpa: 0 }] if section == ".reset")
        );
    }

    #[test]
    fn duplicate_layout_fields_are_rejected() {
        for bytes in [
            b"\xa2\x67actions\x80\x67actions\x80".as_slice(),
            b"\xa3\x67actions\x80\x66dt:dtb\x64.dtb\x66dt:dtb\x64.dtb",
        ] {
            assert!(Manifest::parse(bytes).is_err());
        }
        let action: Value = ciborium::from_reader(
            b"\xa3\x64type\x64load\x67section\x66.reset\x63gpa\x00".as_slice(),
        )
        .unwrap();
        for field in ["type", "section", "gpa"] {
            let mut duplicate = action.clone();
            let fields = duplicate.as_map_mut().unwrap();
            let existing = fields
                .iter()
                .find(|(key, _)| key.as_text() == Some(field))
                .unwrap()
                .clone();
            fields.push(existing);
            assert!(Action::parse(duplicate).is_err());
        }
    }
}
