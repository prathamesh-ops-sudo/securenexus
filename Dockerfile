FROM node:20-slim AS base
WORKDIR /app

LABEL org.opencontainers.image.source="https://github.com/prathamesh-ops-sudo/securenexus"
LABEL org.opencontainers.image.description="SecureNexus - AI-Powered Security Operations Platform"
LABEL org.opencontainers.image.vendor="Arica Technologies"

FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci

FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM base AS runner
ENV NODE_ENV=production
ENV PORT=5000

RUN groupadd --gid 1001 securenexus && \
    useradd --uid 1001 --gid securenexus --shell /bin/false --create-home securenexus

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist

RUN chown -R securenexus:securenexus /app

USER securenexus

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "const http=require('http');const r=http.get('http://localhost:5000/api/ops/health',s=>{process.exit(s.statusCode===200?0:1)});r.on('error',()=>process.exit(1));r.setTimeout(4000,()=>{r.destroy();process.exit(1)})"

CMD ["node", "dist/index.cjs"]
