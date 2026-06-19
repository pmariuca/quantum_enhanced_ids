FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o quantum_backend .

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/quantum_backend .
CMD ["./quantum_backend"]