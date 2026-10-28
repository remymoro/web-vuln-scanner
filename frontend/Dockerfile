FROM node:24.15.0-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.28.0-alpine3.21
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=nginx:nginx /app/dist/frontend/browser /usr/share/nginx/html
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
