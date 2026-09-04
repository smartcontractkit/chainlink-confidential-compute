module github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/host

go 1.26.6

require (
	github.com/smartcontractkit/chainlink-common v0.11.2-0.20260903173259-a8f860eb5f61
	github.com/smartcontractkit/chainlink-confidential-compute v0.0.0
	github.com/smartcontractkit/chainlink-protos/cre/go v0.0.0-20260804191526-b7a850ae7648
	github.com/stretchr/testify v1.12.1
	github.com/things-go/go-socks5 v0.1.1
	go.opentelemetry.io/otel v1.46.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.46.0
	go.opentelemetry.io/otel/metric v1.46.0
	go.opentelemetry.io/otel/sdk v1.46.0
	go.opentelemetry.io/otel/sdk/metric v1.46.0
	go.uber.org/zap v1.28.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/doyensec/safeurl v0.2.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mdlayher/vsock v1.2.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/smartcontractkit/libocr v0.0.0-20260810200708-618b5bf7f342 // indirect
	github.com/smartcontractkit/tdh2/go/tdh2 v0.0.0-20241009175230-e6634ab1b071 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/grpc v1.83.1 // indirect
)

replace github.com/smartcontractkit/chainlink-confidential-compute => ../../..
