package main

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

const DomainSeparator = "CONFIDENTIAL_COMPUTE_PAYLOAD"

func main() {
	// Create attestor.
	attester, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Fatalf("Cannot open NSM session: %v", err)
	}

	// Generate attestation containing a basic ExecuteResponse as user data.
	resp := ExecuteResponse{
		RequestID: sha256.Sum256([]byte("test-request-id")),
		Outputs:   []byte("test-output"),
	}
	res, err := attester.Send(&request.Attestation{
		UserData: resp.UserDataHash(),
	})
	if err != nil {
		log.Fatalf("Cannot send attestation: %v", err)
	}
	log.Printf("Generated attestation: %x", res.Attestation.Document)

	// Continue printing "Hello, world!" every 5 seconds to keep the enclave alive.
	for x := range 1000 {
		log.Default().Printf("Hello, world! %d\n", x)
		time.Sleep(time.Second * 5)
	}
}

type ExecuteResponse struct {
	RequestID   [32]byte      `json:"requestID"`
	Outputs     []byte        `json:"outputs"`
	Config      EnclaveConfig `json:"config"`
	Attestation []byte        `json:"attestation"`
}

func (er *ExecuteResponse) UserDataHash() []byte {
	data := append([]byte{}, er.RequestID[:]...)
	data = append(data, []byte(DomainSeparator)...)
	data = append(data, []byte("\nExecuteResponse\n")...)
	data = append(data, er.Outputs...)
	data = append(data, er.Config.Hash()...)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

type EnclaveConfig struct {
	Signers   [][]byte `json:"signers"`
	PublicKey []byte   `json:"publicKey"`
	T         uint32   `json:"t"`
	F         uint32   `json:"f"`
}

func (ec *EnclaveConfig) Hash() []byte {
	var data []byte
	data = append(data, []byte(DomainSeparator)...)
	data = append(data, []byte("\nEnclaveConfig\n")...)
	for _, signer := range ec.Signers {
		data = append(data, signer...)
	}
	data = append(data, ec.PublicKey...)
	t := make([]byte, 4)
	binary.LittleEndian.PutUint32(t, ec.T)
	data = append(data, t...)
	f := make([]byte, 4)
	binary.LittleEndian.PutUint32(f, ec.F)
	data = append(data, f...)
	hash := sha256.Sum256(data)
	return hash[:]
}
