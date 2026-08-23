.PHONY: fmt fmt-check lint lint-all-features test test-fast test-all bench sla schema-check compose-check ci doc clean run doctor

run:
	cargo run -p av-harness --bin agentvisord

doctor:
	cargo run -q -p av-cli --bin avctl -- doctor

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

# Fast inner loop: unit tests only (~4 s vs ~195 s for the full suite;
# covers ~54% of tests). Use during development; run `make test` before
# pushing.
test-fast:
	cargo test --workspace --lib

test-all:
	cargo test --workspace --all-features

# Heavy SLA / perf measurement (prints the numbers recorded in BENCHMARKS.md; see docs)
sla:
	ulimit -n 65536 && RUN_HEAVY_PERF=1 cargo test --workspace --release -- --ignored --nocapture sla_

bench:
	cargo bench --workspace

doc:
	RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D warnings" cargo doc --workspace --all-features --no-deps

schema-check:
	for schema in schemas/*.json; do node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$$schema" || exit 1; done
	cargo run -q -p av-cli -- manifest-validate manifests/bridge.example.yaml
	cargo run -q -p av-cli -- config-validate config/harness.example.toml
	cargo run -q -p av-cli -- config-validate config/harness.docker.toml
	cargo run -q -p av-cli -- config-validate config/harness.container.toml

compose-check:
	docker compose -f docker/docker-compose.yml config >/dev/null
	docker compose -f docker/docker-compose.minimal.yml config >/dev/null

ci: fmt-check lint-all-features test test-all doc schema-check
	cargo check --workspace --no-default-features
	cargo check --workspace --all-features

clean:
	cargo clean
