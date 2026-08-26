# Cross-compiles rather than emulating: the build stage always runs on the
# builder's native architecture and Go emits a binary for the target. Building
# an amd64 image on an arm64 Mac therefore costs nothing extra.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal/ internal/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/tlsa-dnsendpoint-controller .

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /out/tlsa-dnsendpoint-controller /tlsa-dnsendpoint-controller
USER 65532:65532
ENTRYPOINT ["/tlsa-dnsendpoint-controller"]
