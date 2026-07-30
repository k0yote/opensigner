# Pinned by digest: a tag can be repointed at a different image at any time.
FROM node:24-alpine3.21@sha256:b8f7c9056af700568c1ce76173f1c93743fb64ca1343e18cdf3a6ded8985ad3d AS builder

WORKDIR /app

RUN apk add --no-cache curl git make

# D2 is installed from a pinned release tarball verified against a known checksum.
# Piping an install script straight from the network into a shell would let
# whoever controls that endpoint execute arbitrary code in the build, and would
# silently pick up a different version on every rebuild.
ARG D2_VERSION=0.7.1
ARG D2_SHA256_ARM64=ce3a0b985a8f91335a826c254b3a88736fd81afcdd08b58f6c749d2add6864b0
ARG D2_SHA256_AMD64=eb172adf59f38d1e5a70ab177591356754ffaf9bebb84e0ca8b767dfb421dad7
RUN set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
      aarch64|arm64) d2arch=arm64; expected="$D2_SHA256_ARM64" ;; \
      x86_64|amd64)  d2arch=amd64; expected="$D2_SHA256_AMD64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    tarball="d2-v${D2_VERSION}-linux-${d2arch}.tar.gz"; \
    curl -fsSLO "https://github.com/terrastruct/d2/releases/download/v${D2_VERSION}/${tarball}"; \
    echo "${expected}  ${tarball}" | sha256sum -c -; \
    tar -xzf "$tarball"; \
    make -C "d2-v${D2_VERSION}" install; \
    rm -rf "$tarball" "d2-v${D2_VERSION}"

RUN corepack enable && corepack prepare pnpm@10.28.2 --activate

# Manifests first, so the dependency layer stays cached across content edits.
# .npmrc must be present or the install will not honour the supply-chain settings
# it carries.
COPY package.json pnpm-lock.yaml .npmrc ./

# The registry token is mounted as a BuildKit secret rather than passed as a build
# arg. Build args are recorded in image metadata and readable with `docker
# history`; a secret mount exists only for the duration of this layer.
#
# CI=true tells pnpm it is non-interactive, so it reports a dependency mismatch
# instead of waiting on a confirmation prompt that can never arrive.
ENV CI=true
RUN --mount=type=secret,id=node_auth_token \
    NODE_AUTH_TOKEN="$(cat /run/secrets/node_auth_token 2>/dev/null || true)" \
    pnpm install --frozen-lockfile

COPY . .

RUN pnpm build

# Runtime: a static file server over the prerendered output.
#
# The build is full-static, so nothing here needs Node, pnpm, or the build
# dependency tree — which also keeps that tree's advisories out of the served
# image. Pinned by digest: a tag can be repointed at a different image at any time.
FROM nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752

COPY --from=builder /app/dist/public /usr/share/nginx/html
COPY docs_nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 4173
