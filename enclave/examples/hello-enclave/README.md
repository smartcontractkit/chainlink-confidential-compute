## Enclave example -- "Hello Enclave"
This is an example app that can be run in an AWS Nitro Enclave and produces an attestation. This simple enclave is useful for generating test attestations.

Instructions to run:
1. Build the enclave Docker image: `docker build . -t hello-enclave`
2. Build the .eif from the Docker image: `nitro-cli build-enclave --docker-uri hello-enclave:latest --output-file hello-enclave.eif`
3. Start your enclave: `nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path hello-enclave.eif --debug-mode`
4. Find the enclave running: `nitro-cli describe-enclaves`
5. Use its ID to check its console output (including its attestation): `nitro-cli console --enclave-name hello-enclave`