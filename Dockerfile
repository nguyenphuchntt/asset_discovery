# syntax=docker/dockerfile:1.7

# ============================================================
# Stage 1: builder — compile Go binary with CGO (libpcap required)
# ============================================================
FROM golang:1.25-bookworm AS builder

# Build-time dependencies:
#   libpcap-dev   — headers for github.com/google/gopacket/pcap
#   gcc           — CGO compiler
#   ca-certificates — verify HTTPS during go mod download
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        gcc \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy module files first — cache layer when only source changes
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source tree
COPY . .

# Build arguments for version stamping
ARG VERSION=dev
ARG BUILD_TIME=unknown

# Build flags:
#   CGO_ENABLED=1       — required by gopacket/pcap
#   -trimpath           — strip local paths from binary
#   -ldflags="-s -w"    — strip debug info, reduce size
#   -X main.version     — inject version string
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
        -o /out/discovery \
        ./cmd/discovery

# ============================================================
# Stage 2: runtime — minimal image with libpcap shared library
# ============================================================
FROM debian:bookworm-slim AS runtime

# Runtime dependencies:
#   libpcap0.8   — shared library used by the binary at runtime
#   libcap2-bin  — setcap tool to grant capabilities to the binary (live mode)
#   ca-certificates — TLS for any outbound HTTPS calls
#   tzdata       — correct timezone handling
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        libcap2-bin \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security (UID 1001)
RUN groupadd --system --gid 1001 discovery \
    && useradd  --system --uid 1001 --gid discovery \
                --no-create-home --shell /usr/sbin/nologin \
                --comment "passivediscovery service" \
                discovery

# Application layout
WORKDIR /opt/passivediscovery

# Copy binary from builder stage
COPY --from=builder /out/discovery /opt/passivediscovery/discovery

# Bundle default OUI lookup table (3.7MB)
COPY internal/oui/oui.csv /opt/passivediscovery/oui.csv

# Pre-create writable directories and assign ownership
RUN mkdir -p /data/output /data/db /pcaps \
    && chown -R discovery:discovery /data /opt/passivediscovery \
    && chmod 0755 /opt/passivediscovery/oui.csv \
    && setcap cap_net_raw,cap_net_admin+ep /opt/passivediscovery/discovery

USER discovery

# Default environment — override with `docker run -e` or compose
ENV DISCOVERY_OUTPUT_DIR=/data/output \
    DISCOVERY_DB_PATH=/data/db/discovery.db \
    DISCOVERY_OUI=/opt/passivediscovery/oui.csv \
    DISCOVERY_LOG_LEVEL=info \
    DISCOVERY_OFFLINE_AFTER=15m

# Entry point — binary
ENTRYPOINT ["/opt/passivediscovery/discovery"]
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="passivediscovery" \
      org.opencontainers.image.description="Passive network asset discovery service" \
      org.opencontainers.image.source="https://github.com/yourorg/passivediscovery" \
      org.opencontainers.image.licenses="MIT"