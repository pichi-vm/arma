# Hand-tuned Fedora cargo spec for this workspace.
#
# Copr SCM method is make_srpm. .copr/Makefile builds the SRPM:
# it vendors crates (network is allowed then), packs this git
# tree as Source0, and packs the vendor tree as Source1.
# vendor/ is not committed. %%build stays offline.
#
# Host package only. tatu is a bare-metal artifact dependency
# linked into /usr/bin/arma. This RPM does not install a guest
# image, kernel, or firmware file.
#
# Distro cargo is the stable channel. Artifact dependencies
# ("bindeps") are still unstable, so %%build exports
# RUSTC_BOOTSTRAP=1, which makes cargo accept the [unstable]
# table. cargo-rpm-macros 28 already does this for
# -Z avoid-dev-deps; rust-toolset on EL does not, so set it
# here too.
#
# %%build_rustflags normally add an RPM package note via
# -Clink-arg=-Wl,-dT,.... rust-lld rejects -Wl while linking
# tatu, so those link arguments are omitted. Optimization and
# debuginfo stay.
#
# %%cargo_prep redirects crates.io only. Git crates are
# appended from packaging/cargo-vendor-git.toml. Regenerate
# that file from `cargo vendor --locked --versioned-dirs`
# when the burrow, devtree, or pmi revision changes. Keep
# only the git [source.*] tables. %%cargo_prep also deletes
# .cargo/, so [unstable] bindeps is written again here.
# Fedora cargo-rpm-macros already set [net] offline; EL
# rust-toolset macros do not, so add it only when missing.

%bcond_with check

# Keep crate sources out of the payload. arma ships one binary.
%global cargo_install_lib 0

# No -Wl package note. See the header comment.
%global _package_note_status 0
%global build_rustflags -Copt-level=3 -Cdebuginfo=2 -Ccodegen-units=1 -Cstrip=none -Cforce-frame-pointers=yes

%global crate arma

Name:           arma
Version:        0.1.0
Release:        1%{?dist}
Summary:        PMI builder for pichi-vm

# Linked crates are Apache-2.0, MIT, or a dual license that offers one
# of those (0BSD, BSD-2-Clause, BSD-3-Clause, Unlicense, Zlib).
License:        Apache-2.0 AND MIT
URL:            https://github.com/pichi-vm/arma
Source0:        %{crate}-%{version}.tar.gz
Source1:        %{crate}-%{version}-vendor.tar.xz

# tatu is built for the host arch's bare-metal target. Other arches
# have no artifact dependency in Cargo.toml.
ExclusiveArch:  x86_64 aarch64

%ifarch x86_64
%global tatu_target x86_64-unknown-none
%endif
%ifarch aarch64
%global tatu_target aarch64-unknown-none
%endif

BuildRequires:  rust >= 1.88
BuildRequires:  cargo

# Cargo macros must be available before %%prep runs.
%if 0%{?rhel}
BuildRequires:  rust-toolset
%else
BuildRequires:  cargo-rpm-macros >= 26
%endif

# Crates linked into the binary. Path members (tatu, dtb2acpi,
# dtb2e820) are this source tree, not bundled third-party crates.
# Regenerate from:
#   cargo tree -p arma --edges no-build,no-dev,no-proc-macro \
#     --prefix none --format '{p}'
Provides:       bundled(crate(adler2)) = 2.0.1
Provides:       bundled(crate(aho-corasick)) = 1.1.5
Provides:       bundled(crate(anstream)) = 1.0.0
Provides:       bundled(crate(anstyle)) = 1.0.14
Provides:       bundled(crate(anstyle-parse)) = 1.0.0
Provides:       bundled(crate(anstyle-query)) = 1.1.5
Provides:       bundled(crate(anyhow)) = 1.0.104
Provides:       bundled(crate(arrayvec)) = 0.7.8
Provides:       bundled(crate(cfg-if)) = 1.0.5
Provides:       bundled(crate(ciborium)) = 0.2.2
Provides:       bundled(crate(ciborium-io)) = 0.2.2
Provides:       bundled(crate(ciborium-ll)) = 0.2.2
Provides:       bundled(crate(clap)) = 4.6.7
Provides:       bundled(crate(clap_builder)) = 4.6.7
Provides:       bundled(crate(clap_lex)) = 1.1.1
Provides:       bundled(crate(colorchoice)) = 1.0.5
Provides:       bundled(crate(crc32fast)) = 1.5.3
Provides:       bundled(crate(devtree)) = 0.1.0
Provides:       bundled(crate(flate2)) = 1.1.10
Provides:       bundled(crate(goblin)) = 0.10.7
Provides:       bundled(crate(half)) = 2.7.1
Provides:       bundled(crate(is_terminal_polyfill)) = 1.70.2
Provides:       bundled(crate(log)) = 0.4.34
Provides:       bundled(crate(memchr)) = 2.8.3
Provides:       bundled(crate(miniz_oxide)) = 0.9.1
Provides:       bundled(crate(plain)) = 0.2.3
Provides:       bundled(crate(pmi)) = 0.1.0
Provides:       bundled(crate(regex)) = 1.13.1
Provides:       bundled(crate(regex-automata)) = 0.4.18
Provides:       bundled(crate(regex-syntax)) = 0.8.11
Provides:       bundled(crate(ruzstd)) = 0.9.1
Provides:       bundled(crate(scroll)) = 0.13.0
Provides:       bundled(crate(serde)) = 1.0.229
Provides:       bundled(crate(serde_core)) = 1.0.229
Provides:       bundled(crate(simd-adler32)) = 0.3.10
Provides:       bundled(crate(strsim)) = 0.11.1
Provides:       bundled(crate(thiserror)) = 2.0.21
Provides:       bundled(crate(twox-hash)) = 2.1.5
Provides:       bundled(crate(utf8parse)) = 0.2.2
Provides:       bundled(crate(vm-fdt)) = 0.3.0
Provides:       bundled(crate(zerocopy)) = 0.8.63

%global _description %{expand:
Build a Portable Machine Image from a kernel, optional initrd, and
command line. The tatu boot stub is compiled with arma and stored
inside the arma binary.}

%description %{_description}

%prep
%autosetup -n %{crate}-%{version} -p1 -a1
%cargo_prep -v vendor
printf '\n' >> .cargo/config.toml
cat packaging/cargo-vendor-git.toml >> .cargo/config.toml
cat >> .cargo/config.toml << 'EOF'

[unstable]
bindeps = true
EOF
grep -q '^offline' .cargo/config.toml || printf '\n[net]\noffline = true\n' >> .cargo/config.toml

%generate_buildrequires
# Prebuilt core for the bare-metal tatu target. Fedora and RHEL >= 10
# ship rust-std-static-x86_64-unknown-none. They ship
# aarch64-unknown-none-softfloat, not aarch64-unknown-none. RHEL 9
# ships neither none target, so epel-9 and centos-stream-9 fail here.
echo "rust-std-static-%{tatu_target}"
echo "lld"

%build
# Use -- to pass Cargo flags through the RPM macros.
export RUSTC_BOOTSTRAP=1
export CARGO_NET_OFFLINE=true
%cargo_build -- --locked

%install
export RUSTC_BOOTSTRAP=1
export CARGO_NET_OFFLINE=true
%cargo_install -- --locked

# Tests fetch kernels through burrow. Copr %%build has no network.
%if %{with check}
%check
export RUSTC_BOOTSTRAP=1
%cargo_test
%endif

%files
%license LICENSE
%doc README.md
%{_bindir}/arma

%changelog
* Tue Oct 27 2026 Nathaniel McCallum <nathaniel@mccallum.life> - 0.1.0-1
- Initial host package for Copr.
