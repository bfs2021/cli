# syntax=docker/dockerfile:1

# Vibgrate CLI image — the public, Apache-2.0 `vg` / `vibgrate` command.
#
# A thin container over the ESM CLI build (`dist/cli.js`, produced by tsup with
# @vibgrate/core-open bundled in). The image is the CLI in a container, so it
# inherits the CLI's version verbatim — keeping `image.tag == @vibgrate/cli
# version`, the property the SBOM/attestation chain relies on.
#
# Build context is the repo root:
#   docker build -t vibgrate/cli .

# ---------------------------------------------------------------------------
# Stage 1 — build the CLI from source.
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim AS build

ENV PNPM_HOME=/pnpm
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

WORKDIR /app
COPY . .

RUN pnpm install --frozen-lockfile

# bundle:grammars vendors the tree-sitter .wasm grammars, then tsup builds the
# CLI with @vibgrate/core-open bundled into dist/.
RUN pnpm build

# Verify the build output.
RUN test -f dist/cli.js \
 && head -1 dist/cli.js | grep -q '#!/usr/bin/env node'

# ---------------------------------------------------------------------------
# Stage 2 — minimal runtime with only the CLI's production dependencies.
# @vibgrate/core-open is bundled into dist/ by tsup, so it is dropped before the
# clean production install; web-tree-sitter / tree-sitter-wasms / typescript
# remain (they ship their own assets / load at runtime).
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim AS runtime

ARG VERSION=0.0.0-dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Vibgrate CLI" \
      org.opencontainers.image.description="Local codebase intelligence for AI coding agents: deterministic code graph + MCP server, drift reporting, and version-correct library docs" \
      org.opencontainers.image.vendor="Vibgrate" \
      org.opencontainers.image.url="https://vibgrate.com" \
      org.opencontainers.image.source="https://github.com/vibgrate/cli" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

WORKDIR /app

COPY --from=build /app/dist ./dist
COPY --from=build /app/grammars ./grammars
COPY --from=build /app/package.json ./package.json

# Install only runtime deps. core-open is bundled into dist/, so drop the
# workspace reference (a leftover `workspace:*` spec aborts `npm install` with
# EUNSUPPORTEDPROTOCOL), along with devDependencies and scripts.
RUN npm pkg delete dependencies.@vibgrate/core-open \
 && npm pkg delete devDependencies \
 && npm pkg delete scripts \
 && npm install --omit=dev --no-audit --no-fund --no-package-lock \
 && npm cache clean --force

# Run as the unprivileged user that ships with the base image.
USER node

# Scanned projects are bind-mounted here; e.g. `docker run -v "$PWD:/work" ...`.
WORKDIR /work

ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]
