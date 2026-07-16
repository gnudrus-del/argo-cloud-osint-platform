FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-slim AS runtime
LABEL org.opencontainers.image.title="Argo OSINT — experimental Next.js console"
LABEL org.opencontainers.image.description="Frozen/experimental prototype frontend — NOT the production UI. See STATUS.md."
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/gnudrus-del/argo-cloud-osint-platform"

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin argo

COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/next.config.mjs ./next.config.mjs

RUN chown -R argo:argo /app
USER argo

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.status<500?0:1)).catch(()=>process.exit(1))" || exit 1

CMD ["npm", "start"]
