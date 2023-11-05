FROM golang:1.19 AS build-stage

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /downdetector-exporter

FROM gcr.io/distroless/base-debian12 AS build-release-stage

WORKDIR /
COPY --from=build-stage /downdetector-exporter /downdetector-exporter
EXPOSE 9313
USER nonroot:nonroot
ENTRYPOINT ["/downdetector-exporter"]

