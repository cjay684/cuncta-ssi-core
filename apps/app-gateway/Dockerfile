FROM node:20-alpine AS base
WORKDIR /app
RUN corepack enable
COPY . .
RUN pnpm install --frozen-lockfile

FROM node:20-alpine AS runner
WORKDIR /app
RUN addgroup -S app && adduser -S app -G app
COPY --from=base /app /app
USER app
ENV NODE_ENV=production
EXPOSE 3010
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:3010/healthz >/dev/null || exit 1
CMD ["node", "--import", "tsx", "apps/app-gateway/src/index.ts"]
