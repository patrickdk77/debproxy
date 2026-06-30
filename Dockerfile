FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/debproxy ./cmd/debproxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/debproxy /usr/local/bin/debproxy
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["debproxy"]
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

