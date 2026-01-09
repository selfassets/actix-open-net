# Build stage
FROM rust:1.87-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    mkdir -p src/crypto && \
    echo "" > src/lib.rs

# Build dependencies only
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Copy actual source code
COPY src ./src

# Build the actual binary
RUN touch src/main.rs src/lib.rs && \
    cargo build --release

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/actix-open-net /app/vmess

# Create config directory and add default config
RUN mkdir -p /app/config /app/certs

# Copy example config as default
COPY config.example.json /app/config/config.json

# Copy default self-signed certs (for testing, replace with real certs in production)
COPY certs/ /app/certs/

# Default config file location
ENV VMESS_CONFIG=/app/config/config.json

EXPOSE 10086

ENTRYPOINT ["/app/vmess"]
CMD ["--config", "/app/config/config.json", "--server"]
