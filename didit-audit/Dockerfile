FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000
# Run migrations, then start the HTTP server.
CMD ["sh", "-c", "npx tsx src/migrate.ts && npx tsx src/start.ts"]
