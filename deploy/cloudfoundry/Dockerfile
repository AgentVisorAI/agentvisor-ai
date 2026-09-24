# Build the standard image first, then add the CF deployment configuration.
# Example: docker build --build-arg AGENTVISOR_IMAGE=agentvisor-base:local \
#   -f deploy/cloudfoundry/Dockerfile -t registry.example.com/agentvisor-ai:cf .
ARG AGENTVISOR_IMAGE=agentvisor-base:local
FROM ${AGENTVISOR_IMAGE}
COPY --chown=65532:65532 deploy/cloudfoundry/harness.toml /app/config/harness.cloudfoundry.toml
ENV AV_CONFIG=/app/config/harness.cloudfoundry.toml
