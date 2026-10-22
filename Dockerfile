# debproxy - APT proxy and snapshot publisher for Debian repositories
# docker run -d -p 8080:8080 \
#   -v /etc/debproxy/config.yaml:/etc/debproxy/config.yaml:ro \
#   -v /etc/debproxy/signing:/etc/debproxy/signing:ro \
#   -v /var/lib/debproxy/keys:/var/lib/debproxy/keys:ro \
#   patrickdk/debproxy

ARG BUILD_FROM_PREFIX

FROM ${BUILD_FROM_PREFIX}golang:alpine AS builder
RUN apk --no-cache add gcc musl-dev git
WORKDIR /go/src/debproxy/
COPY . /go/src/debproxy/
ARG BUILD_VERSION
ARG BUILD_DATE
ARG BUILD_REF
ARG BUILD_GOARCH
ARG BUILD_GOOS
RUN export GOPROXY_DISABLED=direct \
 && go mod verify \
 && CGO_ENABLED=0 GOAMD64=v2 go build -trimpath -buildmode=pie \
    -ldflags "-s -w" \
    -o /debproxy ./cmd/debproxy

FROM alpine AS libs
RUN apk --no-cache add ca-certificates tzdata

FROM scratch
COPY --from=libs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=libs /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /lib/ld-musl-*.so.1 /lib/
COPY --from=builder /debproxy /debproxy

WORKDIR /
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/debproxy"]
CMD ["serve", "--config", "/etc/debproxy/config.yaml"]

ARG BUILD_VERSION
ARG BUILD_DATE
ARG BUILD_REF
LABEL maintainer="Patrick Domack (patrickdk@patrickdk.com)" \
  Description="DebProxy APT Proxy server for Debian DEB Files" \
  org.label-schema.schema-version="1.0" \
  org.label-schema.build-date="${BUILD_DATE}" \
  org.label-schema.name="debproxy" \
  org.label-schema.description="APT Proxy server for Debian DEB Files" \
  org.label-schema.url="https://github.com/patrickdk77/debproxy" \
  org.label-schema.usage="https://github.com/patrickdk77/debproxy/tree/master/README.md" \
  org.label-schema.vcs-url="https://github.com/patrickdk77/debproxy" \
  org.label-schema.vcs-ref="${BUILD_REF}" \
  org.label-schema.version="${BUILD_VERSION}" \
  org.opencontainers.image.authors="Patrick Domack (patrickdk@patrickdk.com)" \
  org.opencontainers.image.created="${BUILD_DATE}" \
  org.opencontainers.image.title="debproxy" \
  org.opencontainers.image.description="APT Proxy server for Debian DEB Files" \
  org.opencontainers.image.version="${BUILD_VERSION}" \
  org.opencontainers.image.licenses="MIT" \
  org.opencontainers.image.ref.name="debproxy" \
  version="${BUILD_VERSION}"
