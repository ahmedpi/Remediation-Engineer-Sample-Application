FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS runtime
RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/certs \
    && openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout /etc/nginx/certs/dev-key.pem \
        -out /etc/nginx/certs/dev-cert.pem \
        -subj "/CN=localhost"
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
