// This root module represents the minimal TCB of all applications we run in enclaves.
// Dependencies should seldom be added here.
module github.com/smartcontractkit/chainlink-confidential-compute

go 1.26.4

require (
	github.com/doyensec/safeurl v0.2.2
	github.com/hf/nsm v0.0.0-20220930140112-cd181bd646b9
	github.com/mdlayher/vsock v1.2.1
	github.com/smartcontractkit/tdh2/go/tdh2 v0.0.0-20241009175230-e6634ab1b071
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.49.0
	golang.org/x/sync v0.20.0
	google.golang.org/protobuf v1.36.11
)

require github.com/rogpeppe/go-internal v1.14.1 // indirect

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
