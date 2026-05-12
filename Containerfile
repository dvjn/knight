FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.3-alpine AS build
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

ENV GOPATH=/app/.cache
COPY go.mod go.sum ./
RUN --mount=type=cache,target=${GOPATH} \
    go mod download

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
COPY . .
RUN --mount=type=cache,target=${GOPATH} \
    go build -buildvcs=false -ldflags '-s -w' -o bin/knight ./cmd/knight

FROM docker.io/alpine/git:v2.49.1 AS app

WORKDIR /app
COPY --from=build /app/bin/knight /app/bin/knight

ENTRYPOINT ["/app/bin/knight"]
