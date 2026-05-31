FROM golang:1.21-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o quantum_backend .

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/quantum_backend .
CMD ["./quantum_backend"]
