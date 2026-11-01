# syntax=docker.io/docker/dockerfile:1

##################################################
## "build" stage
##################################################

FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS build

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG SOURCE_DATE_EPOCH

WORKDIR /src/
COPY ./ ./
RUN go test -v ./...
RUN CGO_ENABLED=0 \
	GOOS="${TARGETOS-}" \
	GOARCH="${TARGETARCH-}" \
	GOARM="$([ "${TARGETARCH-}" != 'arm' ] || printf '%s' "${TARGETVARIANT#v}")" \
	go build -o ./simpleidp ./cmd/simpleidp/
RUN test -z "$(readelf -x .interp ./simpleidp 2>/dev/null)"

WORKDIR /rootfs/
RUN install -DTm 0555 /src/simpleidp ./simpleidp
RUN install -DTm 0644 /etc/ssl/certs/ca-certificates.crt ./etc/ssl/certs/ca-certificates.crt
RUN install -dm 0700 -o 18227 -g 18227 ./var/lib/simpleidp/
RUN mkdir -m 1777 ./run/ ./tmp/

##################################################
## "main" stage
##################################################

FROM scratch AS main

COPY --from=build /rootfs/ /

USER 18227:18227

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --start-interval=1s --retries=3 CMD ["/simpleidp", "healthcheck"]

ENTRYPOINT ["/simpleidp"]
