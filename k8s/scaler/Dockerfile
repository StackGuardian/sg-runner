# sg-runner-scaler: sizes the runner StatefulSet (see k8s/README.md,
# "Autoscaling"). Build from k8s/scaler:
#   docker build -t sg-runner-scaler:dev .
#   docker buildx build --platform linux/amd64,linux/arm64 -t sg-runner-scaler:dev .

ARG GO_VERSION=1.27

# Cross-compiles on the build host's platform: no emulation needed.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
  go build -trimpath -ldflags="-s -w" -o /out/sg-runner-scaler ./cmd/sg-runner-scaler

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/sg-runner-scaler /sg-runner-scaler
USER 65532:65532
EXPOSE 9090
ENTRYPOINT ["/sg-runner-scaler"]
