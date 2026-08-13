FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install --omit=dev --package-lock=false
COPY src ./src
ENV NODE_ENV=production
CMD ["npx", "tsx", "src/index.ts"]
