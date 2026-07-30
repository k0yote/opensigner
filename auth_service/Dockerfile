# Pinned by digest: a tag can be repointed at a different image at any time.
FROM node:24-alpine3.22@sha256:191c9f0080fcbbc6547a85dc0ff7988072214a355aabdc1d2ec55a7dae5eea8a AS deps

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.28.2 --activate

# Manifests only, so the dependency layer stays cached across source edits.
# .npmrc must be present or the install will not honour the supply-chain
# settings it carries.
COPY package.json pnpm-lock.yaml .npmrc ./
RUN pnpm install --frozen-lockfile

# ---------------------------------------------------------------------------

FROM deps AS builder

COPY . .

# Compile ahead of time so the runtime image executes plain node with no
# TypeScript loader in the request path.
RUN pnpm build

# ---------------------------------------------------------------------------
# Migration stage. The schema tool is a devDependency and needs the TypeScript
# config file, so it lives here rather than in the image that serves traffic:
# its dependency tree is large and carries advisories of its own, none of which
# belong in a process handling requests.
FROM builder AS migrate

ENV NODE_ENV=production

ENTRYPOINT ["pnpm", "exec", "better-auth", "migrate", "--config", "src/server.ts", "--yes"]

# ---------------------------------------------------------------------------
# Runtime: production dependencies only.
FROM node:24-alpine3.22@sha256:191c9f0080fcbbc6547a85dc0ff7988072214a355aabdc1d2ec55a7dae5eea8a AS runtime

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.28.2 --activate

COPY package.json pnpm-lock.yaml .npmrc ./
RUN pnpm install --frozen-lockfile --prod

COPY --from=builder /app/dist ./dist

# Several library safety checks -- including the refusal to boot on a default
# secret -- are gated on production mode, so set it in the image rather than
# relying on the deployment to supply it.
ENV NODE_ENV=production

RUN addgroup -S appgroup && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /app

EXPOSE 3000

USER appuser

ENTRYPOINT ["node", "dist/server.js"]
