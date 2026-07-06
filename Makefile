.PHONY: ci fmt lint build test fix install uninstall version release formula

# single source of truth: the [package] version line in Cargo.toml
VERSION := $(shell grep -m1 '^version' Cargo.toml | cut -d'"' -f2)

# one-shot gate: format check + strict clippy + build + tests (what CI would run)
ci: fmt lint build test

fmt:
	cargo fmt --check

lint:
	cargo clippy --all-targets -- -D warnings

build:
	cargo build --all-targets

test:
	cargo test

# `make fix` to auto-apply formatting instead of just checking
fix:
	cargo fmt

# install the release binary to ~/.cargo/bin (on PATH); --force overwrites an older build
install:
	cargo install --path . --force

uninstall:
	cargo uninstall lictor

version:
	@echo $(VERSION)

# tag + push the version in Cargo.toml as vX.Y.Z. Bump Cargo.toml and commit first.
# Gates on a clean tree, a green `ci`, and a not-yet-used tag so the tag can't drift.
release: ci
	@git diff-index --quiet HEAD -- || { echo "working tree dirty — commit before releasing"; exit 1; }
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then echo "tag v$(VERSION) already exists — bump version in Cargo.toml first"; exit 1; fi
	git tag "v$(VERSION)"
	git push origin "v$(VERSION)"
	$(MAKE) formula

# rewrite the vendored formula's url + sha256 for the current tag. The tarball only
# exists once the tag is pushed, so this runs after `release` (or standalone to refresh).
# ponytail: pins GitHub's auto-generated archive sha — stable in practice, but if GitHub
# ever changes archive compression, switch to an uploaded release-asset tarball.
formula:
	@url="https://github.com/sladg/lictor/archive/refs/tags/v$(VERSION).tar.gz"; \
	sha=$$(curl -fsSL "$$url" | shasum -a 256 | cut -d' ' -f1); \
	[ -n "$$sha" ] || { echo "could not fetch tarball — is v$(VERSION) pushed?"; exit 1; }; \
	sed -i.bak -e "s|url \".*\"|url \"$$url\"|" -e "s|sha256 \".*\"|sha256 \"$$sha\"|" dist/homebrew/lictor.rb; \
	rm -f dist/homebrew/lictor.rb.bak; \
	echo "formula pinned to v$(VERSION) ($$sha)"
