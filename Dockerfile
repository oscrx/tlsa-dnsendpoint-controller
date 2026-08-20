# Cross-compiles rather than emulating: the build stage always runs on the
# builder's native architecture and Go emits a binary for the target. Building
# an amd64 image on an arm64 Mac therefore costs nothing extra.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal/ internal/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/tlsa-dnsendpoint-controller .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/tlsa-dnsendpoint-controller /tlsa-dnsendpoint-controller
USER 65532:65532
ENTRYPOINT ["/tlsa-dnsendpoint-controller"]
