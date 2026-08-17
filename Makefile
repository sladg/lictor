.PHONY: ci fmt lint build test fix install uninstall version release formula llms llms-check

# single source of truth: the [package] version line in Cargo.toml
VERSION := $(shell grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
TAP_REPO := git@github.com:sladg/homebrew-tap.git

# the docs bundle, assembled the same way by `llms` and `llms-check`.
# LC_ALL=C because sort's collation is locale-dependent: en_US.UTF-8 folds case
# and orders `README.md` among the lowercase names, while C puts it first. Without
# this the file's contents depend on who ran `make llms`, and the check below
# fails for whoever has the other locale.
LLMS = { cat README.md; git ls-files 'docs/**/*.md' | LC_ALL=C sort | xargs cat; }

# one-shot gate: format check + strict clippy + build + tests + docs freshness.
# `.github/workflows/ci.yml` runs exactly this, so a local run and CI cannot
# disagree about what passing means.
ci: fmt lint build test llms-check

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
	$(LLMS) > llms.txt

# llms.txt is generated, so it silently goes stale whenever docs change and
# nobody reruns `make llms` — it had already drifted by two features
llms-check:
	@tmp=$$(mktemp); $(LLMS) > $$tmp; \
	  diff -q $$tmp llms.txt > /dev/null; ok=$$?; rm -f $$tmp; \
	  [ $$ok -eq 0 ] || { echo "llms.txt is stale — run 'make llms' and commit the result"; exit 1; }

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
