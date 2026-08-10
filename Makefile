.PHONY: fmt lint test test-all bench sla ci doc clean

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

lint-all-features:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace

test-all:
	cargo test --workspace --all-features

# Heavy SLA / perf measurement (writes BENCHMARKS.md numbers; see docs)
sla:
	RUN_HEAVY_PERF=1 cargo test --workspace --release -- --ignored --nocapture sla_

bench:
	cargo bench --workspace

doc:
	RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps

ci: fmt-check lint test doc
	cargo check --workspace --no-default-features
	cargo check --workspace --all-features

clean:
	cargo clean
