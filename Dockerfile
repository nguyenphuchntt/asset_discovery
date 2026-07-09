# syntax=docker/dockerfile:1.7

FROM golang:1.25-bookworm AS builder

# Install prerequisites dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        gcc \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG VERSION=dev
ARG BUILD_TIME=unknown

# Build the project
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
        -o /out/discovery \
        ./cmd/discovery


FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        libcap2-bin \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Add discovery user
RUN groupadd --system --gid 1001 discovery \
    && useradd  --system --uid 1001 --gid discovery \
                --no-create-home --shell /usr/sbin/nologin \
                --comment "passivediscovery service" \
                discovery

WORKDIR /opt/passivediscovery

COPY --from=builder /out/discovery /opt/passivediscovery/discovery
COPY internal/oui/oui.csv /opt/passivediscovery/oui.csv

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

ENTRYPOINT ["/opt/passivediscovery/discovery"]
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="passivediscovery" \
      org.opencontainers.image.description="Passive network asset discovery service" \
      org.opencontainers.image.source="https://github.com/yourorg/passivediscovery" \
      org.opencontainers.image.licenses="MIT"