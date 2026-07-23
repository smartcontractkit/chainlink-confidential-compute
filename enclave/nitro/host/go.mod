module github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/host

go 1.26.4

require (
	github.com/smartcontractkit/chainlink-common v0.11.2-0.20260714160921-4033d0253977
	github.com/smartcontractkit/chainlink-confidential-compute v0.0.0-20260723152523-f8319c05c128
	github.com/smartcontractkit/chainlink-protos/cre/go v0.0.0-20260622152157-c8e129347b8b
	github.com/stretchr/testify v1.11.1
	go.uber.org/zap v1.27.1
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/doyensec/safeurl v0.2.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mdlayher/vsock v1.2.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/smartcontractkit/libocr v0.0.0-20250912173940-f3ab0246e23d // indirect
	github.com/smartcontractkit/tdh2/go/tdh2 v0.0.0-20241009175230-e6634ab1b071 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/smartcontractkit/chainlink-confidential-compute => ../../..
