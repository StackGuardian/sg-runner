# sg-runner-scaler: sizes the runner StatefulSet (see k8s/README.md,
# "Autoscaling"). The image also carries /sg-runner-steps, the step broker
# running in each runner pod (see k8s/docs/steps-api.md). Build from k8s/scaler:
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
  go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/sg-runner-scaler ./cmd/sg-runner-steps

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/sg-runner-scaler /sg-runner-scaler
COPY --from=build /out/sg-runner-steps /sg-runner-steps
USER 65532:65532
EXPOSE 9090
ENTRYPOINT ["/sg-runner-scaler"]
