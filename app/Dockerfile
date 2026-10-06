# Reference container used to exercise the Trivy scan in CI.

# Stage 1: install production dependencies with npm.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
# mkdir keeps the COPY below working when there are no dependencies yet.
RUN npm install --omit=dev --no-audit --no-fund && mkdir -p node_modules

# Stage 2: runtime image. npm, npx, corepack and yarn are removed because the
# server only needs the node binary, and they ship their own dependencies
# that would otherwise show up in the image scan.
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app

RUN rm -rf /usr/local/lib/node_modules /opt/yarn-* \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg && \
    addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 -G nodejs

COPY --from=deps /app/node_modules ./node_modules
COPY package.json server.js ./

# Run as a dedicated unprivileged user.
USER nodejs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/ >/dev/null || exit 1

CMD ["node", "server.js"]
