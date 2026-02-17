FROM node:20-slim AS base
WORKDIR /app

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

COPY package.json package-lock.json ./
RUN npm ci --production

COPY --from=builder /app/dist ./dist

EXPOSE 5000

CMD ["node", "dist/index.cjs"]
