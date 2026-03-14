# ── Stage 1: builder ───────────────────────────────────────────────────────
# edition = "2024" requires rustc ≥ 1.85; rust:1.85-slim-bookworm is the
# minimum version that compiles this crate.
FROM rust:1.85-slim-bookworm AS builder

# Install only the libraries needed to link the binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Layer caching: compile all dependencies before touching our source ──────
# Copy manifests first — these layers are re-used as long as deps don't change
COPY Cargo.toml Cargo.lock ./

# The workspace Cargo.toml lists src-tauri as a member, which isn't present
# in this build context (excluded by .dockerignore). Remove it from the
# workspace members list so cargo can resolve the workspace cleanly.
RUN sed -i 's/members = \["src-tauri"\]/members = []/' Cargo.toml

# Create minimal stub sources — just enough to let cargo compile the external
# dependency graph. The stub itself may fail to compile; that's fine because
# by the time cargo reaches our code all third-party crates are compiled and
# will be cached in this Docker layer.
RUN mkdir -p src && \
    printf 'pub fn _stub() {}\n' > src/lib.rs && \
    printf 'fn main() {}\n'      > src/main.rs

RUN cargo build --release -p anya-security-core 2>/dev/null || true

# Remove stub artifacts so our code is recompiled cleanly in the next step
RUN find target/release -maxdepth 2 \( \
        -name "anya-security-core" \
        -o -name "anya_security_core*" \
    \) -exec rm -f {} + 2>/dev/null || true

# ── Compile the real source ─────────────────────────────────────────────────
COPY src ./src

RUN cargo build --release -p anya-security-core

# Verify the binary was produced and strip debug symbols to minimise size
RUN ls -lh target/release/anya-security-core && \
    strip target/release/anya-security-core


# ── Stage 2: minimal runtime image ─────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Runtime dependencies only — no build tools, no compilers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Run as a dedicated non-root user — no login shell, no home directory writes
RUN groupadd -r anya && \
    useradd  -r -g anya -s /sbin/nologin -M anya

# Copy the stripped binary and rename it to the short 'anya' command
COPY --from=builder /build/target/release/anya-security-core /usr/local/bin/anya

# Verify dynamic library linkage — surfaces unexpected deps at build time
RUN ldd /usr/local/bin/anya || true

# Volumes
# /samples  — mount PE/ELF files to analyse (recommend read-only)
# /output   — analysis results written here
# /config   — optional config file override (~/.config/anya/config.toml layout)
VOLUME ["/samples", "/output", "/config"]

USER anya

LABEL org.opencontainers.image.title="Anya" \
      org.opencontainers.image.description="Privacy-first PE/ELF malware analyser" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.source="https://github.com/elementmerc/anya"

ENTRYPOINT ["/usr/local/bin/anya"]
CMD ["--help"]
