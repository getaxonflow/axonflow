# Multi-stage build for React frontend
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage - serve with nginx
FROM nginx:alpine

# Copy built app from builder stage
COPY --from=builder /app/build /usr/share/nginx/html

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create non-root user
RUN addgroup -g 1001 -S axonflow && \
    adduser -S -D -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G axonflow -g axonflow axonflow

# Change ownership of nginx directories
RUN chown -R axonflow:axonflow /var/cache/nginx && \
    chown -R axonflow:axonflow /var/log/nginx && \
    chown -R axonflow:axonflow /etc/nginx/conf.d

# Create pid file directory
RUN touch /var/run/nginx.pid && \
    chown -R axonflow:axonflow /var/run/nginx.pid

# Switch to non-root user
USER axonflow

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]