.PHONY: ci fmt lint build test fix install uninstall

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
