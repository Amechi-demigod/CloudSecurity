# syntax=docker/dockerfile:1
# Production image for the UI: static Vite build served by unprivileged nginx,
# which also reverse-proxies /api/ to the backend (BACKEND_URL).

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
USER 101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
