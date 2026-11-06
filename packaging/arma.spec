# Tatu uses the bare-metal linker, which cannot accept GCC package notes.
%global _package_note_status 0

Name:           arma
Version:        0.1.0~dev
Release:        1%{?buildtag}%{?dist}
Summary:        PMI builder for Pichi

License:        Apache-2.0 AND MIT
URL:            https://github.com/pichi-vm/arma
Source0:        %{name}-%{version}.tar.gz
ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  git
BuildRequires:  lld
%ifarch x86_64
BuildRequires:  rust-std-static-x86_64-unknown-none
%endif
%ifarch aarch64
BuildRequires:  rust-std-static-aarch64-unknown-none-softfloat
%endif

%description
PMI builder for Pichi.

%prep
%autosetup

%build
export CARGO_HOME="$PWD/.cargo-home"
export RUSTC_BOOTSTRAP=1
cargo build --locked --release --bin arma

%install
install -Dpm0755 target/release/arma %{buildroot}%{_bindir}/arma

# Preserve license and notice files from the fetched dependencies.
find .cargo-home -type f \( -iname 'license*' -o -iname 'licence*' -o \
    -iname 'copying*' -o -iname 'notice*' -o -iname 'copyright*' \) \
    -exec install -Dm0644 '{}' '%{buildroot}%{_licensedir}/%{name}/dependencies/{}' \;

%files
%license %{_licensedir}/%{name}/dependencies/
%license LICENSE
%doc README.md
%{_bindir}/arma
