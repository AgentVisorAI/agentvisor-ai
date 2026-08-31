# AgentVisor AI hosted API — production image.
#
# Design goals:
#   - Portable: standard Node 22 slim, deploys as-is to Fly.io, Cloud Run,
#     Render, Railway, Kubernetes, or any Docker host.
#   - Small: multi-stage build ships only compiled JS + runtime deps.
#   - Secure: non-root user; the final CMD does invoke `sh -c` for the
#     migrate→exec chain, but runs under dumb-init as PID 1 (signals
#     forwarded, zombies reaped) — no long-lived shell, and no shell
#     access from a running container without an explicit `docker exec`.
#     Healthcheck reads /readyz.
#   - Deterministic: `npm ci` locks the tree, base image pinned to a digest.
#
# Rebuild the digest pins periodically to pull in patched base images:
#   docker manifest inspect node:22-slim | grep digest

# ---------- build stage ----------
# For fully reproducible builds, replace the tag with a digest, e.g.
# `node:22-slim@sha256:<sha>`. Fetch the current digest with:
#   docker manifest inspect node:22-slim | grep digest | head -1
FROM node:26-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY prisma ./prisma
RUN npx prisma generate

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# NOTE: we intentionally do NOT `npm prune --omit=dev` here. `prisma` is
# a runtime dependency (the entrypoint runs `prisma migrate deploy` on
# boot), and every other devDep is small enough that trading a few MB
# of image size for one less pruning-caused footgun is worth it.

# ---------- runtime stage ----------
FROM node:26-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false

# `openssl` needed by Prisma for the Postgres TLS handshake at runtime.
# `dumb-init` gives us a proper PID 1 so SIGTERM propagates cleanly (fast
# shutdowns are important on autoscaling platforms).
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates dumb-init \
    && rm -rf /var/lib/apt/lists/*

# Delete the base image's globally-installed npm + npx CLIs. They ship
# a large transitive dep graph (brace-expansion, tar, deepmerge-ts,
# sigstore, …) that Trivy flags as HIGH/CRITICAL. The runtime never
# invokes npm — the entrypoint runs the local prisma binary directly —
# so nothing here depends on the global tools.
RUN rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY package.json ./

# Node's `node` user (uid 1000) exists in the base image already.
USER node

# The hosting platform (Fly / Cloud Run / Render / …) sets PORT; we listen on
# whatever they hand us. 8080 is a portable default.
ENV PORT=8080
EXPOSE 8080

# Cheap liveness probe. Container orchestrators (Fly checks, Cloud Run health,
# k8s liveness) all understand this format. Uses /readyz — a 200 there means
# both the API process and the database it depends on are healthy, so an
# unhealthy DB drains traffic instead of returning 500s.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# dumb-init reaps zombies + forwards signals so `docker stop` and Fly's rolling
# deploys finish in <100ms instead of the default 10s SIGKILL wait.
# Invoke prisma via its local binary (`node_modules/.bin/prisma`) so we
# don't need `npx` (deleted above) and so the runtime doesn't have to
# reach out to npm to fetch anything on boot.
ENTRYPOINT ["dumb-init", "--"]
CMD ["sh", "-c", "./node_modules/.bin/prisma migrate deploy && node dist/index.js"]
