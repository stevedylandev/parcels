# ── Builder ──────────────────────────────────────────────────────────────────
FROM rust:1.87-bookworm AS builder

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src

# Copy source, templates, and static assets
COPY src ./src
COPY templates ./templates
COPY static ./static

# Touch source files so Cargo sees them as newer than the stub binary
RUN find src -name "*.rs" | xargs touch
RUN cargo build --release

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/parcels ./parcels
COPY --from=builder /app/static ./static
COPY --from=builder /app/templates ./templates

EXPOSE 3012

CMD ["./parcels"]
