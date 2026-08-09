.PHONY: ci fmt lint build test fix install uninstall version release formula llms

# single source of truth: the [package] version line in Cargo.toml
VERSION := $(shell grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
TAP_REPO := git@github.com:sladg/homebrew-tap.git

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
llms:
	{ cat README.md; find docs -name '*.md' | sort | xargs cat; } > llms.txt

release: ci llms
	@git update-index -q --refresh
	@git diff-index --quiet HEAD -- || { echo "working tree dirty — commit before releasing"; exit 1; }
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then echo "tag v$(VERSION) already exists — bump version in Cargo.toml first"; exit 1; fi
	@printf "release lictor \033[1mv$(VERSION)\033[0m? (bump Cargo.toml first if wrong) [y/N] "; \
	read a; [ "$$a" = y ] || { echo "aborted"; exit 1; }
	git tag "v$(VERSION)"
	git push origin "v$(VERSION)"
	$(MAKE) formula

# clone the tap, pin url + sha256 to the current tag, commit + push. The tarball only
# exists once the tag is pushed, so this runs after `release`. Needs push access to $(TAP_REPO).
# ponytail: pins GitHub's auto-generated archive sha — stable in practice, but if GitHub
# ever changes archive compression, switch to an uploaded release-asset tarball.
formula:
	@url="https://github.com/sladg/lictor/archive/refs/tags/v$(VERSION).tar.gz"; \
	sha=$$(curl -fsSL "$$url" | shasum -a 256 | cut -d' ' -f1); \
	[ -n "$$sha" ] || { echo "could not fetch tarball — is v$(VERSION) pushed?"; exit 1; }; \
	tmp=$$(mktemp -d); \
	git clone -q "$(TAP_REPO)" "$$tmp"; \
	( cd "$$tmp" && \
	  sed -i.bak -e "s|url \".*\"|url \"$$url\"|" -e "s|sha256 \".*\"|sha256 \"$$sha\"|" Formula/lictor.rb && \
	  rm -f Formula/lictor.rb.bak && \
	  git commit -aqm "lictor v$(VERSION)" && git push -q ) \
	  || { rm -rf "$$tmp"; echo "tap update failed"; exit 1; }; \
	rm -rf "$$tmp"; \
	echo "tap updated to v$(VERSION) ($$sha)"
