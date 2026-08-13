FROM cgr.dev/chainguard/rust:latest-dev AS build
USER root
RUN apk add --no-cache cmake curl-dev
USER 65532
WORKDIR /src
ADD --checksum=sha256:6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452 https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/onnx/model.onnx /tmp/models/model.onnx
ADD --checksum=sha256:be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037 https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/tokenizer.json /tmp/models/tokenizer.json
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY schemas ./schemas
RUN cargo build --locked --release -p ab-harness --features full --bin agent-bridge -p ab-cli --bin abctl
RUN mkdir -p /tmp/runtime-root/data /tmp/runtime-root/spool

FROM cgr.dev/chainguard/glibc-dynamic:latest AS runtime
WORKDIR /app
COPY --from=build /src/target/release/agent-bridge /usr/local/bin/agent-bridge
COPY --from=build /src/target/release/abctl /usr/local/bin/abctl
COPY --from=build --chown=65532:65532 /tmp/models /app/models
COPY --from=build --chown=65532:65532 /tmp/runtime-root/ /app/
COPY --chown=65532:65532 schemas ./schemas
COPY --chown=65532:65532 config/harness.docker.toml ./config/harness.docker.toml
COPY --chown=65532:65532 config/policies ./config/policies
COPY --chown=65532:65532 config/tool-schemas ./config/tool-schemas
COPY --chown=65532:65532 manifests ./manifests
USER 65532
EXPOSE 8484
ENV AB_CONFIG=/app/config/harness.docker.toml
ENTRYPOINT ["agent-bridge"]
