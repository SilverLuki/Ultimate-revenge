FROM node:18-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --only=production

# Copy the main application
COPY server.js ./

# Expose the port
EXPOSE 3000

# Run the server
CMD ["node", "server.js"]