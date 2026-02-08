FROM node:20-alpine AS build

WORKDIR /app

# Copy npm config if present (.npmrc or .npmrc.example for default registry)
COPY .npmrc* ./
RUN if [ ! -f .npmrc ] && [ -f .npmrc.example ]; then cp .npmrc.example .npmrc; fi

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
