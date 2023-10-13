ARG BUILDPLATFORM="linux/amd64"
ARG BUILDERIMAGE="golang:1.21-bullseye"
#ARG BASEIMAGE="gcr.io/distroless/static:nonroot"
ARG BASEIMAGE="golang:1.21-bullseye"

FROM --platform=$BUILDPLATFORM $BUILDERIMAGE as builder

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""
ARG LDFLAGS

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOARM=${TARGETVARIANT}

WORKDIR /go/src/github.com/MoOyeg/rh-registry-gatekeeper-provider

COPY . .

RUN go mod tidy && go build -o provider provider.go && rm .env

FROM $BASEIMAGE

WORKDIR /

COPY --from=builder /go/src/github.com/MoOyeg/rh-registry-gatekeeper-provider .

RUN chgrp -R 0 /provider \
  && chmod -R g+rwx /provider

USER 1001

ENTRYPOINT ["/provider"]