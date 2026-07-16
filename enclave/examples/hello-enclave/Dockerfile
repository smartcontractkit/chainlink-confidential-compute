FROM golang:alpine as build

WORKDIR /

RUN mkdir -p source

COPY . ./source/

WORKDIR source/

RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o build/enclave hello.go

FROM scratch

WORKDIR /

COPY --from=build /source/build/enclave ./

CMD ["/enclave"]