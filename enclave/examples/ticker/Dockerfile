FROM golang:alpine as build

WORKDIR /

RUN mkdir -p source

COPY . ./source/

WORKDIR source/

RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o build/enclave ticker.go

FROM amazonlinux:latest

WORKDIR /

RUN dnf upgrade -y && \
    dnf install -y \
    chrony \
    procps-ng \
    iproute && \
    dnf clean all

# For more: https://aws.amazon.com/blogs/compute/its-about-time-microsecond-accurate-clocks-on-amazon-ec2-instances/
RUN echo "refclock PHC /dev/ptp0 poll 0 offset 0 prefer" > /etc/chrony.conf && \
    echo "makestep 1.0 3" >> /etc/chrony.conf

COPY --from=build /source/build/enclave ./

RUN echo '#!/bin/sh' > /start.sh && \
    echo 'chronyd' >> /start.sh && \
    echo 'sleep 5' >> /start.sh && \
    echo 'exec /enclave' >> /start.sh && \
    chmod +x /start.sh

ENTRYPOINT ["/start.sh"]