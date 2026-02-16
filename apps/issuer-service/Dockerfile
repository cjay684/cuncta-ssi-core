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
EXPOSE 3002
CMD ["node", "--import", "tsx", "apps/issuer-service/src/index.ts"]
