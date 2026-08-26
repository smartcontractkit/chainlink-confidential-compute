// This module is intended to be imported by external repositories that need to
// launch local enclaves in their E2E tests. Keep its dependency set to the root
// module plus testify so it stays cheap to consume.
module github.com/smartcontractkit/chainlink-confidential-compute/tests/testhelpers

go 1.26.4

// The root module is required at a real pseudo-version, not v0.0.0, so that
// external repositories can consume this module without adding their own
// replace directive. The replace below only applies to in-repo builds.
require (
	github.com/smartcontractkit/chainlink-confidential-compute v0.0.0-20260810193839-ed12934f0671
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/doyensec/safeurl v0.2.4 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/hf/nsm v0.0.0-20220930140112-cd181bd646b9 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/mdlayher/vsock v1.2.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/smartcontractkit/tdh2/go/tdh2 v0.0.0-20241009175230-e6634ab1b071 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/smartcontractkit/chainlink-confidential-compute => ../../
