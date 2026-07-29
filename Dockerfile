# ── Build stage ────────────────────────────────────────────────────────────────
# Use the official Rust image so we get the full toolchain for compilation.
FROM rust:1.94-slim AS builder

# pkg-config is required by several crate build scripts (e.g. ring).
# No OpenSSL needed — reqwest uses rustls, sqlx uses runtime-tokio-rustls.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first — Docker caches this layer separately from the source,
# so a code-only change doesn't trigger a full dependency re-download.
COPY Cargo.toml Cargo.lock ./

# Pre-compile dependencies with a dummy main.
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --locked && \
    rm -f target/release/deps/shieldgrid_core*

# Copy real source and build the actual binary.
COPY src ./src
RUN cargo build --release --locked

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Slim Debian image — no Rust toolchain, just the compiled binary.
FROM debian:bookworm-slim AS runtime

# CA certificates let HTTPS requests (to OpenSearch) work inside the container.
# curl is used by the docker-compose healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/shieldgrid-core .

EXPOSE 3000

CMD ["./shieldgrid-core"]
