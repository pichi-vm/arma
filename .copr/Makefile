# Copr "make srpm" entry point. Source0 is this git tree. Source1 is a
# vendor tarball produced here. vendor/ is not committed.
SHELL := /bin/bash

srpm:
	set -euo pipefail; \
	root=$$(git rev-parse --show-toplevel); \
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
