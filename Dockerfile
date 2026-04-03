FROM node:20-alpine

# Non-root user for isolation
RUN addgroup -S ctf && adduser -S ctf -G ctf

WORKDIR /app

# Install deps first (layer cache)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app source
COPY server.js ./
COPY public/ ./public/

# The app writes flag parts and key material to /tmp and /var/cache/app at startup.
# Ensure those paths are writable by the ctf user.
RUN mkdir -p /tmp/.cache /var/cache/app && \
    chown -R ctf:ctf /tmp/.cache /var/cache/app /app

USER ctf

EXPOSE 3000

CMD ["node", "server.js"]
