# Multi-stage build for React frontend with Vite
FROM node:18-alpine as builder

# Set working directory
WORKDIR /app

# Copy package files
COPY src/frontend/package*.json ./

# Install dependencies (including dev dependencies for build)
RUN npm ci

# Copy source code
COPY src/frontend/ .

# Build the application
RUN npm run build

# Development stage
FROM node:18-alpine as development

WORKDIR /app

# Copy package files
COPY src/frontend/package*.json ./

# Install all dependencies (including dev)
RUN npm ci

# Copy source code
COPY src/frontend/ .

# Expose port
EXPOSE 3000

# Start development server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# Production stage with nginx
FROM nginx:alpine

# Copy built assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom nginx configuration
COPY deployment/nginx-frontend.conf /etc/nginx/conf.d/default.conf

# Create nginx user and set permissions
RUN addgroup -g 1001 -S nginx && \
    adduser -S -D -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx && \
    chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d

# Switch to nginx user
USER nginx

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
