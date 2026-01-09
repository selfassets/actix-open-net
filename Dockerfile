# Build stage
FROM rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy source code
COPY src ./src

# Build the actual binary
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/actix-open-net /app/vmess

# Create config directory
RUN mkdir -p /app/config

# Default config file location
ENV VMESS_CONFIG=/app/config/config.json

EXPOSE 10086

ENTRYPOINT ["/app/vmess"]
CMD ["--config", "/app/config/config.json"]
