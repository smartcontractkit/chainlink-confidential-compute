# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copy the entire repository to the build stage
COPY . .

# Build the config-tracker binary
RUN cd /app/enclave/config-tracker && \
    CGO_ENABLED=0 GOOS=linux go build -o /config-tracker .

# Final stage
FROM alpine:latest

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /config-tracker /config-tracker

# Command to run the application
ENTRYPOINT ["/config-tracker"]