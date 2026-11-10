FROM node:22-slim

ENV NODE_ENV=production
WORKDIR /srv

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY src ./src
COPY public ./public

USER node
ENV SITE_HOST=0.0.0.0
CMD ["node", "src/server.js"]
