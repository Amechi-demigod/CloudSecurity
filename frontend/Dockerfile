# syntax=docker/dockerfile:1
# Production image for the UI: static Vite build served by unprivileged nginx,
# which also reverse-proxies /api/ to the backend (BACKEND_URL).
#
# Also ships the public marketing website (repo-root website/, served on-prem
# for SITE_HOSTNAMES: deploy/onprem/nginx/cnapp-access.sh). It lives outside this
# build context, so it comes in as a named context:
#   docker build --build-context website=website frontend        (from the repo root)
# (CI: build-contexts in .github/workflows/ci.yml; dev: additional_contexts in
# docker-compose.yml). The stage below only exists to fail clearly without it:
# a --build-context of the same name replaces it.
FROM alpine:3.22 AS website
RUN echo "ERROR: build with --build-context website=<repo>/website (see frontend/Dockerfile)" >&2 && exit 1

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.28-alpine AS runtime
ENV BACKEND_URL=http://backend:8000 \
    NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1 \
    NGINX_ENTRYPOINT_QUIET_LOGS=1
# The image's default site listens on 8080 too; ours replaces it.
USER root
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
COPY --from=website *.html favicon.svg /usr/share/nginx/site/
COPY --from=website assets /usr/share/nginx/site/assets
USER 101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
