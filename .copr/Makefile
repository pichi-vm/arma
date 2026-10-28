# Copr make_srpm entry point. Copr cds into the clone and runs
# `make -f .copr/Makefile srpm` with spec= and outdir=.
#
# make_srpm has no chroot package list in the Copr UI, so this
# target installs what it needs with dnf (cargo, rust, rpm-build,
# tar, xz, gzip). Do not require git: Copr already provides the
# tree as cwd. Override DNF (e.g. DNF=true) when the host already
# has those tools, such as GitHub Actions with apt + rustup.
#
# Source0 is this tree tarball. Source1 is a vendor tarball
# produced here. vendor/ is not committed. RUSTC_BOOTSTRAP=1
# lets cargo vendor accept [unstable] bindeps.
SHELL := /bin/bash
DNF ?= dnf

srpm:
	$(DNF) -y install cargo rust rpm-build tar xz gzip
	set -euo pipefail; \
	root=$$(pwd); \
	workdir=$$(mktemp -d); \
	trap 'rm -rf "$$workdir"' EXIT; \
	version=$$(awk '/^Version:/ { print $$2; exit }' "$(spec)"); \
	name=$$(awk '/^Name:/ { print $$2; exit }' "$(spec)"); \
	mkdir -p "$(outdir)"; \
	cd "$$root"; \
	RUSTC_BOOTSTRAP=1 cargo vendor --locked --versioned-dirs "$$workdir/vendor" \
		>/dev/null; \
	tar -C "$$root" -czf "$$workdir/$$name-$$version.tar.gz" \
		--exclude-vcs \
		--exclude target \
		--exclude vendor \
		--transform "s,^\./,$$name-$$version/," \
		.; \
	tar -C "$$workdir" -cJf "$$workdir/$$name-$$version-vendor.tar.xz" vendor; \
	rpmbuild -bs "$(spec)" \
		--define "_sourcedir $$workdir" \
		--define "_srcrpmdir $(outdir)" \
		--define "_disable_source_fetch 0"
