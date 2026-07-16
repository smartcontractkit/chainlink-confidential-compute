## AWS Nitro Enclave: Confidential HTTP Calls
This enclave application runs on AWS Nitro Enclaves and enables HTTP calls to be made, where a portion of the HTTP request may be encrypted.

### Application Overview
This enclave application accepts an incoming HTTP request and executes it as a proxy. The request is formed as a `ConfidentialHTTPRequest` struct, which includes:
-  `Request`: A request object, which contains:
    - `Url`: URL to be accessed
    - `Method`: POST, GET, etc..
    - `Body`: Body field (can be bytes or string template)
    - `MultiHeaders`: header fields, mapping of keys to templated strings
    - `TemplatePublicValues`: non-sensitive values inserted into body and headers
    - `CustomRootCaCertPem` - custom certificate for if the user has a special TLS certificate chain for accessing their service.
    - `Timeout`: timeout of the request
    - `EncryptOutput`: whether or not to encrypt the output (uses the `san_marino_aes_gcm_encryption_key` defined as a Vault DON secret below)
- `VaultDonSecrets`: A slice of `SecretIdentifier` fields that each contain: 
    - `Key`: identifier of the secret. The values of secrets besides `san_marino_aes_gcm_encryption_key` are injected into the corresponding request's `Body` and `MultiHeaders` fields, once it is decrypted by the enclave.
    - `Namespace`: should be unused.
    - `Owner`: should be unused.

These requests are sent as `CapabilityRequest` objects to the capability of this enclave application (`/enclave/apps/confidential-http/capability/action.go`), which is a binary running in the Chainlink node and not in the enclave. This capability receives the request, then:
- Picks an enclave to process this request using its enclave client (under the hood `/enclave-client/pool.go`).
- Fetches an encryption public key from that enclave. These are managed by the enclave at `/enclave/services/keychain/keychain.go`
- Sends a capability request to the Vault DON capability to produce decryption key shares of each secret, encrypted under the public key of the chosen enclave.
- Sends the marhsalled `ConfidentialHTTPRequest` along with all materials related to the Vault DON Secrets to the enclave within a signed `ComputeRequest` struct.

This orchestration logic is handled by `/capabilities/framework/executor.go` Note that it will be a committee of n nodes executing this same logic together, since Chainlink capabilities are run in "Decentralized Oracle Networks" aka committees of nodes, rather than a single node executing the logic. 

The enclave then receives signed `ComputeRequest` structs,  all coming from these nodes at around the same time. The enclave uses the confidential compute framework (see `/enclave/nitro/host/host.go` and `/enclave/server/server.go`), and waits until it receives `2f+1` valid (signatures verified at `/enclave/services/signature-verifier/ed25519_signature_verifier.go`) unique compute request structs (f being some acceptable number of faulty nodes that is usually set to (n-1)/3). Once it receives a quorum of shares, it picks the first one in the batch (they are all identical), and uses its private key to decrypt the secret key shares, and then combines the secret key shares (using TDH2 at `/enclave/services/combiner/tdh2easycombiner.go`) into the plaintext secrets. Once it has those plaintext secrets it passes them along with the marshalled `ConfidentialHTTPRequest` to the confidential HTTP enclave application (`/enclave/apps/confidential-http/app/app.go`).

The Confidential HTTP enclave application injects the plaintext secrets into the request body & headers, makes the request, and returns the result, which is encrypted under the `san_marino_aes_gcm_encryption_key` secret key if it is provided as a Vault DON secret in the request. That final result is marshalled, and then attested to using the attestation service, (`/enclave/services/attestor/nitro_attestor.go`) and returned as bytes to the caller of the capability.

### APIs
The following flows are supported by this application:
- `/publicKeys`: fetch the current live ephemeral public keys for the application.
- `/config`: (operator-only) set the config of the application.
- `/requests`: execute a list of HTTP requests through the application.

For the `/requests` endpoint, the app uses the standard `ComputeRequest` struct. It expects:
- t+f decryption shares per-ciphertext to be provided in the `EncryptedDecryptionKeyShares` field.
- f+1 unique `SignedComputeRequest` requests submitted by the signers that are included in the `EnclaveConfig.Signers` field.
- HTTP requests submitted to conform to the `HTTPEnclaveRequestData` struct.

### Networking
The host program contained in `enclave/nitro/host/host.go` acts as an untrusted proxy for the enclave. It communicates with the enclave over [vsock](https://man7.org/linux/man-pages/man7/vsock.7.html); in order to accept a user request, it parses the requet from the user, then constructs its own HTTP request it sends over the vsock channel to the enclave. 

The host program is also responsible for routing outbound requests from the enclave. In order to do this, it uses [wireguard](https://pkg.go.dev/github.com/seedcx/wireguard-go-vsock#section-readme) to provide a network interface for the enclave that can be easily configured to forward traffic out to the intended IP. Most networking logic is contained in `../../host/setup-host-networking.sh` and `/outbound-https` Since packets are forwarded without any other interaction, TLS sessions are established between the enclave and the destination IP of the outbound request. Consequently, data transmitted over the TLS session is not visible to the untrusted proxy (host), such that secrets can remain private. 

The enclave must maintain a set of root certificates in order to safely communicate with the outside internet. These are copied from the host system and built into the enclave in the  `Dockerfile`.

### Example use
The E2E tests in `/tests/e2e/e2e_test.go` make an end-to-end request of this entire system.