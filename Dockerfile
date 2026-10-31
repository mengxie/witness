# syntax=docker/dockerfile:1

# ---- Build the server and the CLI
FROM node:25-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/sdk/package.json packages/sdk/
COPY packages/cli/package.json packages/cli/
COPY apps/server/package.json apps/server/
RUN npm ci
COPY tsconfig.base.json ./
COPY packages packages
COPY apps apps
RUN npm run build -w @witness/server -w @witness/cli

# ---- The server's production dependencies only
FROM node:25-alpine AS prod-deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/sdk/package.json packages/sdk/
COPY packages/cli/package.json packages/cli/
COPY apps/server/package.json apps/server/
RUN npm ci --omit=dev --workspace=@witness/server

# ---- Runtime: the server bundle, its dependencies, and the witness CLI for operators
FROM node:25-alpine AS runtime
ENV NODE_ENV=production PORT=4000
WORKDIR /app
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/apps/server/dist ./dist
COPY --from=build /app/packages/cli/dist/witness.js ./witness.js
USER node
EXPOSE 4000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4000/health').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"
CMD ["node", "dist/main.js"]
