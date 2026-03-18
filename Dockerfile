FROM node:20-slim AS base
WORKDIR /app

LABEL org.opencontainers.image.source="https://github.com/prathamesh-ops-sudo/securenexus"
LABEL org.opencontainers.image.description="SecureNexus - AI-Powered Security Operations Platform"
LABEL org.opencontainers.image.vendor="Arica Technologies"

# ── Install dependencies ─────────────────────────────────────
FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

# ── Build application ────────────────────────────────────────
FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# ── Production image ─────────────────────────────────────────
FROM base AS runner
ENV NODE_ENV=production
ENV PORT=5000

# Security: run as non-root with no login shell
RUN groupadd --gid 1001 securenexus && \
    useradd --uid 1001 --gid securenexus --shell /bin/false --create-home securenexus

# Install only production dependencies, then clean up
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force && \
    rm -rf /tmp/* /root/.npm

COPY --from=builder /app/dist ./dist

# Security: make node_modules and dist read-only for the app user
RUN chown -R securenexus:securenexus /app && \
    chmod -R 555 /app/dist

USER securenexus

EXPOSE 5000

# Kubernetes-compatible health check with proper timeout
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "const http=require('http');const r=http.get('http://localhost:5000/api/ops/health',s=>{process.exit(s.statusCode===200?0:1)});r.on('error',()=>process.exit(1));r.setTimeout(4000,()=>{r.destroy();process.exit(1)})"

# Use dumb-init pattern via Node's built-in signal handling (see server/index.ts)
CMD ["node", "--max-old-space-size=1024", "dist/index.cjs"]
