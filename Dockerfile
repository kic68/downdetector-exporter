FROM golang:1.24 AS build-stage

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION}" -o /downdetector-exporter

FROM gcr.io/distroless/base-debian13 AS build-release-stage

WORKDIR /
COPY --from=build-stage /downdetector-exporter /downdetector-exporter
EXPOSE 9313
USER nonroot:nonroot
ENTRYPOINT ["/downdetector-exporter"]
