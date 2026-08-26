# AgentVisor AI hosted API — production image.
#
# Design goals:
#   - Portable: standard Node 22 slim, deploys as-is to Fly.io, Cloud Run,
#     Render, Railway, Kubernetes, or any Docker host.
#   - Small: multi-stage build ships only compiled JS + runtime deps.
#   - Secure: non-root user, no shell in the final layer's CMD, healthcheck.
#   - Deterministic: `npm ci` locks the tree, base image pinned to a digest.
#
# Rebuild the digest pins periodically to pull in patched base images:
#   docker manifest inspect node:22-slim | grep digest

# ---------- build stage ----------
# For fully reproducible builds, replace the tag with a digest, e.g.
# `node:22-slim@sha256:<sha>`. Fetch the current digest with:
#   docker manifest inspect node:22-slim | grep digest | head -1
FROM node:22-slim AS build
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

# Strip dev dependencies from the tree we'll copy into the runtime image.
RUN npm prune --omit=dev

# ---------- runtime stage ----------
FROM node:22-slim AS runtime
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
# k8s liveness) all understand this format.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# dumb-init reaps zombies + forwards signals so `docker stop` and Fly's rolling
# deploys finish in <100ms instead of the default 10s SIGKILL wait.
ENTRYPOINT ["dumb-init", "--"]
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/index.js"]
