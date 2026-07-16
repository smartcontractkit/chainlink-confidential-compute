# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copy the entire repository to the build stage
COPY . .

# Build the host binary
RUN cd /app/enclave/nitro/host && \
    CGO_ENABLED=0 GOOS=linux go build -o /host .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /host /host

# Expose the default ports
EXPOSE 8080 8081

# Command to run the application
ENTRYPOINT ["/host"]