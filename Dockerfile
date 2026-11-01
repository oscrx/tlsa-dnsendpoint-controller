# Cross-compiles rather than emulating: the build stage always runs on the
# builder's native architecture and Go emits a binary for the target. Building
# an amd64 image on an arm64 Mac therefore costs nothing extra.
FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal/ internal/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/tlsa-dnsendpoint-controller .

FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/tlsa-dnsendpoint-controller /tlsa-dnsendpoint-controller
USER 65532:65532
ENTRYPOINT ["/tlsa-dnsendpoint-controller"]
