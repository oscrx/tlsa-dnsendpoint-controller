# Cross-compiles rather than emulating: the build stage always runs on the
# builder's native architecture and Go emits a binary for the target. Building
# an amd64 image on an arm64 Mac therefore costs nothing extra.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4@sha256:3102e2c7eeee6e16de01ca3f35c56434696f70702a30b3d564b0244560981bb0 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal/ internal/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/tlsa-dnsendpoint-controller .

FROM gcr.io/distroless/static:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=build /out/tlsa-dnsendpoint-controller /tlsa-dnsendpoint-controller
USER 65532:65532
ENTRYPOINT ["/tlsa-dnsendpoint-controller"]
