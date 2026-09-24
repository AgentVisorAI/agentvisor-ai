# Build and generate Prisma on the same Debian/glibc family as the runtime.
# The runtime contains Node and its libraries, without a shell or package manager.
# Inspect both manifest digests when preparing an image update.
FROM node:22-trixie-slim@sha256:b26b04c123d9ff8ab646ceb18b9d75a1173acf64b9a401094b906d27b29338d4 AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY prisma ./prisma
RUN node node_modules/prisma/build/index.js generate
COPY tsconfig.json ./
COPY database-url.mjs database-url.d.mts ./
COPY src ./src
RUN npm run build
# Prisma is a production dependency because startup applies migrations. Remove
# only declared development dependencies, then regenerate the native client.
RUN npm prune --omit=dev --ignore-scripts --no-audit --no-fund \
    && node node_modules/prisma/build/index.js generate

FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:5ef534d3db0ac0c43bee379af4ae49cfbfc0ef38a46c94c52d87c68f32f34d8a AS runtime
WORKDIR /app
# Debian 13 Distroless includes libssl, zlib, libgcc, CA certificates, and
# timezone data. Preserve its package metadata for complete vulnerability scans.
ENV NODE_ENV=production \
    PATH=/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PORT=8080
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY package.json package-lock.json container-entrypoint.mjs database-url.mjs ./
USER 65532:65532
EXPOSE 8080

# Exec form is required: this image deliberately contains no /bin/sh.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:'+process.env.PORT+'/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["container-entrypoint.mjs"]
