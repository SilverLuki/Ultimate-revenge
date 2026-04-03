FROM node:18-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --only=production

# Copy the rest of the application
COPY server.js ./
COPY public ./public

EXPOSE 3000

CMD ["node", "server.js"]
