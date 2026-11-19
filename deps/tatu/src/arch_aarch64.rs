// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! aarch64 finalization: entry stub, halt/debug, kernel handoff.
//! See ARCHITECTURE.md Part III.
//!
//! Unsafe lives where natural: entry asm, halt, MMIO debug write,
//! final kernel branch. Each block carries `// SAFETY:` (§7.1).

#![allow(unsafe_code)]

// ---------------------------------------------------------------------------
// Entry stub + BOOTINFO storage. Both live in this private
// submodule so `BOOTINFO` is referenced only by the asm `sym`
// below — no other Rust code can read or write it, and the
// optimizer can't fold through the asm boundary.
// ---------------------------------------------------------------------------

mod reset {
    use crate::bootinfo::TatuBootInfo;
    use crate::sections::STACK_SIZE;

    /// The `.tatu.bootinfo` section. Arma overwrites the
    /// placeholder zeros at PMI build time. **Never read from
    /// Rust by name** — see the matching note in arch_x86_64.
    #[used]
    #[unsafe(link_section = ".tatu.bootinfo")]
    static BOOTINFO: TatuBootInfo = TatuBootInfo::ZERO;

    /// Reset stub in `.tatu.reset.aarch64`, which `linker/tatu.ld` places
    /// at GPA 0, the fixed PMI boot address. The x86 stub uses
    /// `.tatu.reset.x86_64` instead.
    ///
    /// SAFETY: PC-relative adrp/add+:lo12: resolves STACK and
    /// BOOTINFO at link time; adding STACK_SIZE yields the top of
    /// the 64 KiB stack. rust_main is the cross-arch lifecycle
    /// entry; it never returns. AAPCS: first arg in X0, so
    /// rust_main receives `bootinfo: &TatuBootInfo`. PMI supplies EL1h with
    /// DAIF masked and MMU/caches off. The softfloat, strict-align target
    /// uses no FP/SIMD or unaligned memory instructions, so it does not rely
    /// on CPACR_EL1 or on permissive SCTLR_EL1 alignment settings.
    /// `no_mangle` keeps the naked entry alive until linker KEEP retains it.
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    #[unsafe(link_section = ".tatu.reset.aarch64")]
    extern "C" fn reset() -> ! {
        core::arch::naked_asm!(
            "adrp x0,  {bootinfo}",
            "add  x0,  x0,  :lo12:{bootinfo}",
            "adrp x16, {stack}",
            "add  x16, x16, :lo12:{stack}",
            "add  x16, x16, {size}",
            "mov  sp,  x16",
            "b    {main}",
            bootinfo = sym BOOTINFO,
            stack    = sym crate::sections::STACK,
            size     = const STACK_SIZE,
            main     = sym crate::rust_main,
        )
    }
}

// ---------------------------------------------------------------------------
// Halt: null VBAR_EL1 + UDF #0 → recursive synchronous abort →
// KVM_EXIT_FAIL_ENTRY (or equivalent).
// ---------------------------------------------------------------------------

#[inline(never)]
pub(crate) fn halt() -> ! {
    // SAFETY: writing xzr to VBAR_EL1 sets the exception vector
    // to address 0; UDF then raises a synchronous exception which
    // cannot be vectored anywhere valid. The vCPU cannot resume.
    unsafe {
        core::arch::asm!("msr vbar_el1, xzr", "udf #0", options(noreturn),);
    }
}

// ---------------------------------------------------------------------------
// KASLR: arm64 randomizes its virtual base from `/chosen/kaslr-seed` (a kernel
// built with CONFIG_RANDOMIZE_BASE reads it and self-relocates). The seed is
// generated at boot, so it is NOT in the measured base DTB. tatu carries
// a trusted overlay (`crate::kaslr`) that adds `/chosen/kaslr-seed`; here we
// patch its placeholder and merge it onto the measured base before the host
// overlay. RNDR is preferred; the counter fallback provides only best-effort
// randomization and can be predicted by the host or guest. Host overlays remain
// forbidden from contributing /chosen/kaslr-seed (validate_host_dtbo rejects it).
// ---------------------------------------------------------------------------

use devtree::{Overlay, Tree};

/// Prepare the DTB the host overlay will be merged onto. aarch64 injects a
/// `/chosen/kaslr-seed`: it patches the trusted kaslr overlay
/// template with a boot-time seed and merges it onto the measured `base`, writing
/// the result into `scratch` and returning that slice. (The x86 counterpart is
/// a no-op that returns `base` unchanged — it randomizes via post-merge
/// relocations.) `scratch` must be large enough for the base plus the seed
/// property (the base is at most the `.tatu.dtb` reservation).
pub(crate) fn prepare_merge_base<'a>(
    base: &'a [u8],
    scratch: &'a mut [u8],
) -> Result<&'a [u8], ()> {
    // Copy the read-only template into a mutable buffer and patch the seed.
    let template = crate::kaslr::KASLR_OVERLAY_TEMPLATE;
    let mut tpl = [0u8; 512];
    let n = template.len();
    if n > tpl.len() {
        return Err(());
    }
    tpl[..n].copy_from_slice(template);
    if !crate::kaslr::patch_overlay_seed(&mut tpl[..n], kaslr_seed()) {
        return Err(());
    }

    let overlay = Overlay::parse(&tpl[..n]).map_err(|_| ())?;
    let base_tree = Tree::parse(base).map_err(|_| ())?;
    let written = crate::merge::merge_into(&base_tree, overlay, scratch).map_err(|_| ())?;
    Ok(&scratch[..written])
}

/// Prefer RNDR; use the virtual counter if unavailable or exhausted.
/// The fallback is only for ordinary-VM KASLR, not cryptographic randomness.
/// A present or unrecognized Realm Services Interface forbids the fallback.
fn kaslr_seed() -> u64 {
    if cpu_has_rndr() {
        for _ in 0..100 {
            let mut val = 0;
            // SAFETY: FEAT_RNG is present and val is a valid writable u64.
            if unsafe { core::arch::aarch64::__rndr(&raw mut val) } == 0 {
                return val;
            }
        }
    }
    if !counter_fallback_allowed() {
        halt();
    }
    let counter: u64;
    // SAFETY: CNTVCT_EL0 is readable at EL1 under the VM timer contract.
    unsafe {
        core::arch::asm!("mrs {c}, cntvct_el0", c = out(reg) counter, options(nostack, nomem, preserves_flags));
    }
    // Spread timing bits without claiming additional entropy. Linux treats a
    // zero KASLR seed as absent, so keep the fallback nonzero.
    counter.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1)
}

/// Probe RSI 1.0 before allowing a weak seed. A real Realm's RMM services this
/// SMC itself; its response is not delegated to the untrusted host. Only the
/// explicit SMCCC "not supported" result permits fallback. In particular, an
/// unsupported RSI revision is not evidence that we are outside a Realm.
fn counter_fallback_allowed() -> bool {
    const RSI_ABI_VERSION: u64 = 0xc400_0190;
    const RSI_REVISION_1_0: u64 = 0x0001_0000;
    const SMCCC_NOT_SUPPORTED: u64 = u64::MAX;
    let status: u64;
    // SAFETY: RSI_ABI_VERSION takes no pointers. Declare caller-saved registers
    // clobbered across the SMC; no host-provided memory or feature bit is used
    // to authorize the counter fallback.
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") RSI_ABI_VERSION => status,
            inout("x1") RSI_REVISION_1_0 => _,
            in("x2") 0u64, in("x3") 0u64, in("x4") 0u64,
            in("x5") 0u64, in("x6") 0u64, in("x7") 0u64,
            clobber_abi("C"),
            options(nostack),
        );
    }
    status == SMCCC_NOT_SUPPORTED
}

/// Whether the CPU implements FEAT_RNG (`ID_AA64ISAR0_EL1.RNDR`, bits 63:60).
fn cpu_has_rndr() -> bool {
    let isar0: u64;
    // SAFETY: ID_AA64ISAR0_EL1 is readable at EL1; no memory or flag effects.
    unsafe {
        core::arch::asm!("mrs {r}, ID_AA64ISAR0_EL1", r = out(reg) isar0, options(nostack, nomem, preserves_flags));
    }
    (isar0 >> 60) & 0xf != 0
}

/// Guest IPA width in bits, from `ID_AA64MMFR0_EL1.PARange` (bits 3:0). Per pmi
/// spec bc7f581 this is the bound for host-supplied addresses in the merged DTB
/// — read from the architectural register, never a hardcoded constant.
pub(crate) fn guest_pa_bits() -> u32 {
    let mmfr0: u64;
    // SAFETY: ID_AA64MMFR0_EL1 is readable at EL1; no memory or flag effects.
    unsafe {
        core::arch::asm!("mrs {r}, ID_AA64MMFR0_EL1", r = out(reg) mmfr0, options(nostack, nomem, preserves_flags));
    }
    match mmfr0 & 0xf {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        6 => 52,
        7 => 56,
        // 5 is 48 bits. Reserved encodings fall back to the same 48 bits.
        _ => 48,
    }
}

// ---------------------------------------------------------------------------
// MergedDtb — typed handle for the merged DTB workspace, the
// argument to `boot_kernel` on aarch64.
// ---------------------------------------------------------------------------

#[derive(Debug, Copy, Clone)]
pub(crate) struct MergedDtb {
    pub gpa: u64,
}

// ---------------------------------------------------------------------------
// Kernel handoff. Loads x0 with the merged DTB GPA, branches to
// the kernel entry. Never returns.
// ---------------------------------------------------------------------------

pub(crate) fn boot_kernel(kernel_bytes: &[u8], dtb: MergedDtb) -> ! {
    let entry = kernel_bytes.as_ptr() as u64;
    // SAFETY: this is the final instruction tatu executes. Per
    // the aarch64 Linux boot protocol the kernel expects
    // `x0 = DTB GPA`, `x1 = x2 = x3 = 0` (reserved, MBZ), and PC at
    // the Image header (offset 0). Tatu's code no longer runs after
    // this branch. Zeroing x1–x3 silences the kernel's "x1-x3 nonzero
    // in violation of boot protocol" warning.
    unsafe {
        core::arch::asm!(
            "mov x0, {dtb}",
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",
            "br  {entry}",
            dtb = in(reg) dtb.gpa,
            entry = in(reg) entry,
            options(noreturn),
        );
    }
}
