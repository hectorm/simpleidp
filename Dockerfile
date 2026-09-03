# syntax=docker.io/docker/dockerfile:1

##################################################
## "build" stage
##################################################

FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/golang:1.27.1-trixie@sha256:9baa6b4187bbb98d240372a8a235ac0bb6b5ddd52bba1431dc2f7c0705862728 AS build

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
	go build -o ./simple-idp ./cmd/simple-idp/
RUN test -z "$(readelf -x .interp ./simple-idp 2>/dev/null)"

WORKDIR /rootfs/
RUN install -DTm 0555 /src/simple-idp ./simple-idp
RUN install -DTm 0644 /etc/ssl/certs/ca-certificates.crt ./etc/ssl/certs/ca-certificates.crt
RUN mkdir -m 1777 ./run/ ./tmp/

##################################################
## "main" stage
##################################################

FROM scratch AS main

COPY --from=build /rootfs/ /

USER 18227:18227
ENTRYPOINT ["/simple-idp"]
