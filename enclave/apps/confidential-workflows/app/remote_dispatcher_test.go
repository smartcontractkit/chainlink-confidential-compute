package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	"github.com/smartcontractkit/chainlink-common/pkg/jsonrpc2"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/confidential-compute/enclave/apps/confidential-workflows/gateway"
	signatureverifier "github.com/smartcontractkit/confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// --- Helpers ---

// jsonRPCHandler wraps a handler function as a JSON-RPC 2.0 HTTP handler.
func jsonRPCHandler(t *testing.T, handler func(method string, params json.RawMessage) (any, error)) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		req, err := jsonrpc2.DecodeRequest[json.RawMessage](body, "")
		if err != nil {
			t.Fatalf("decoding request: %v", err)
		}

		result, handlerErr := handler(req.Method, *req.Params)

		if handlerErr != nil {
			resp := jsonrpc2.Response[json.RawMessage]{
				Version: jsonrpc2.JsonRpcVersion,
				ID:      req.ID,
				Error:   &jsonrpc2.WireError{Code: jsonrpc2.ErrInternal, Message: handlerErr.Error()},
			}
			respBytes, _ := jsonrpc2.EncodeResponse(&resp)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(respBytes)
			return
		}

		resultJSON, _ := json.Marshal(result)
		resultRaw := json.RawMessage(resultJSON)
		resp := jsonrpc2.Response[json.RawMessage]{
			Version: jsonrpc2.JsonRpcVersion,
			ID:      req.ID,
			Result:  &resultRaw,
		}
		respBytes, _ := jsonrpc2.EncodeResponse(&resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}
}

// --- CallCapability tests ---

func TestCallCapability_HappyPath(t *testing.T) {
	// Build a CapabilityResponse that the mock relay will return.
	wantValue := wrapperspb.String("result-value")
	wantAny, err := anypb.New(wantValue)
	require.NoError(t, err)
	wantResp := &sdkpb.CapabilityResponse{
		Response: &sdkpb.CapabilityResponse_Payload{
			Payload: wantAny,
		},
	}
	wantRespBytes, err := proto.Marshal(wantResp)
	require.NoError(t, err)

	signers := newRelaySigners(t, 2)

	srv := httptest.NewServer(jsonRPCHandler(t, func(method string, params json.RawMessage) (any, error) {
		assert.Equal(t, confidentialrelay.MethodCapabilityExec, method)

		var p confidentialrelay.CapabilityRequestParams
		require.NoError(t, json.Unmarshal(params, &p))
		assert.Equal(t, "wf-cap", p.WorkflowID)
		assert.Equal(t, "0x0123456789abcDEF0123456789abCDef01234567", p.Owner)
		assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", p.ExecutionID)
		assert.Empty(t, p.OrgID)
		assert.Equal(t, "17", p.ReferenceID)
		assert.Equal(t, "write_ethereum@1.0.0", p.CapabilityID)
		assert.NotEmpty(t, p.Payload)

		// Verify the payload is a valid base64-encoded CapabilityRequest proto.
		payloadBytes, err := base64.StdEncoding.DecodeString(p.Payload)
		require.NoError(t, err)
		var capReq sdkpb.CapabilityRequest
		require.NoError(t, proto.Unmarshal(payloadBytes, &capReq))
		assert.Equal(t, "write_ethereum@1.0.0", capReq.GetId())

		result := confidentialrelay.CapabilityResponseResult{
			Payload: base64.StdEncoding.EncodeToString(wantRespBytes),
		}
		return signCapabilityBundle(t, result, p, signers), nil
	}))
	defer srv.Close()

	d := NewRemoteDispatcher(
		gateway.NewGatewayClient(srv.URL, nil),
		nil,
		relayDONConfig(signers, 1),
		logger.Test(t),
		nil, nil,
		signatureverifier.NewEd25519SignatureVerifier(),
	)

	inputAny, err := anypb.New(wrapperspb.String("input-data"))
	require.NoError(t, err)

	resp, err := d.CallCapability(context.Background(), "wf-cap", "0x0123456789abcdef0123456789abcdef01234567", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", &sdkpb.CapabilityRequest{
		Id:         "write_ethereum@1.0.0",
		Method:     "Transmit",
		Payload:    inputAny,
		CallbackId: 17,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	respPayload := resp.GetPayload()
	require.NotNil(t, respPayload)

	var gotValue wrapperspb.StringValue
	require.NoError(t, anypb.UnmarshalTo(respPayload, &gotValue, proto.UnmarshalOptions{}))
	assert.Equal(t, "result-value", gotValue.GetValue())
}

func TestCallCapability_RemoteError(t *testing.T) {
	signers := newRelaySigners(t, 2)
	srv := httptest.NewServer(jsonRPCHandler(t, func(_ string, params json.RawMessage) (any, error) {
		var p confidentialrelay.CapabilityRequestParams
		require.NoError(t, json.Unmarshal(params, &p))
		result := confidentialrelay.CapabilityResponseResult{
			Error: "capability execution failed: timeout",
		}
		return signCapabilityBundle(t, result, p, signers), nil
	}))
	defer srv.Close()

	d := NewRemoteDispatcher(
		gateway.NewGatewayClient(srv.URL, nil),
		nil,
		relayDONConfig(signers, 1),
		logger.Test(t),
		nil, nil,
		signatureverifier.NewEd25519SignatureVerifier(),
	)

	resp, err := d.CallCapability(context.Background(), "wf-err", "0x0123456789abcdef0123456789abcdef01234567", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", &sdkpb.CapabilityRequest{
		Id:         "write_ethereum@1.0.0",
		Method:     "Transmit",
		CallbackId: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Contains(t, resp.GetError(), "capability execution failed")
}

func TestCallCapability_RPCError(t *testing.T) {
	srv := httptest.NewServer(jsonRPCHandler(t, func(_ string, _ json.RawMessage) (any, error) {
		return nil, assert.AnError
	}))
	defer srv.Close()

	d := NewRemoteDispatcher(
		gateway.NewGatewayClient(srv.URL, nil),
		nil,
		types.EnclaveConfig{},
		logger.Test(t),
		nil, nil,
		signatureverifier.NewEd25519SignatureVerifier(),
	)

	_, err := d.CallCapability(context.Background(), "wf-err", "0x0123456789abcdef0123456789abcdef01234567", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", &sdkpb.CapabilityRequest{
		Id:         "write_ethereum@1.0.0",
		Method:     "Transmit",
		CallbackId: 1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sending capability request")
}

// --- ExecutionHelper integration tests ---

func TestExecutionHelper_GetSecrets_WithRemoteDispatcher(t *testing.T) {
	// When remoteDispatcher is set, GetSecrets delegates to it.
	mockDispatcher := &stubRemoteDispatcher{
		getSecretsFn: func(_ context.Context, _ string, _ [32]byte, req *sdkpb.GetSecretsRequest, _ string, _ string, _ string) ([]*sdkpb.SecretResponse, error) {
			return []*sdkpb.SecretResponse{{
				Response: &sdkpb.SecretResponse_Secret{
					Secret: &sdkpb.Secret{
						Id:        req.GetRequests()[0].GetId(),
						Namespace: req.GetRequests()[0].GetNamespace(),
						Value:     "remote-value",
					},
				},
			}}, nil
		},
	}

	h := &enclaveExecutionHelper{
		remoteDispatcher: mockDispatcher,
		logger:           logger.Test(t),
	}

	resp, err := h.GetSecrets(context.Background(), &sdkpb.GetSecretsRequest{
		Requests: []*sdkpb.SecretRequest{{Id: "KEY", Namespace: "default"}},
	})
	require.NoError(t, err)
	require.Len(t, resp, 1)

	assert.Equal(t, "remote-value", resp[0].GetSecret().Value)
}

// The helper forwards its signed compute requests to the dispatcher on GetSecrets.
func TestExecutionHelper_GetSecrets_ForwardsSignedRequests(t *testing.T) {
	want := []types.SignedComputeRequest{
		{ComputeRequest: types.ComputeRequest{RequestID: [32]byte{1}, AppID: "app-a"}, Signature: []byte("sig-1")},
		{ComputeRequest: types.ComputeRequest{RequestID: [32]byte{1}, AppID: "app-a"}, Signature: []byte("sig-2")},
	}
	stub := &stubRemoteDispatcher{
		getSecretsFn: func(context.Context, string, [32]byte, *sdkpb.GetSecretsRequest, string, string, string) ([]*sdkpb.SecretResponse, error) {
			return nil, nil
		},
	}
	h := &enclaveExecutionHelper{
		remoteDispatcher: stub,
		signedRequests:   want,
		logger:           logger.Test(t),
	}

	_, err := h.GetSecrets(context.Background(), &sdkpb.GetSecretsRequest{
		Requests: []*sdkpb.SecretRequest{{Id: "KEY", Namespace: "default"}},
	})
	require.NoError(t, err)
	assert.Equal(t, want, stub.lastSignedRequests)
}

// toRelaySignedComputeRequests copies every ComputeRequest field plus the signature.
func TestToRelaySignedComputeRequests(t *testing.T) {
	assert.Nil(t, toRelaySignedComputeRequests(nil))

	in := types.SignedComputeRequest{
		ComputeRequest: types.ComputeRequest{
			RequestID:                 [32]byte{1, 2, 3},
			ApplicationRequestID:      "exec-123",
			PublicData:                []byte("pd"),
			Ciphertexts:               [][]byte{[]byte("ct")},
			CiphertextNames:           []string{"n"},
			EnclaveEphemeralPublicKey: []byte("epk"),
			MasterPublicKey:           []byte("mpk"),
			AppID:                     "app",
			Version:                   "v1",
		},
		Signature: []byte("sig"),
	}
	out := toRelaySignedComputeRequests([]types.SignedComputeRequest{in})
	require.Len(t, out, 1)
	assert.Equal(t, in.RequestID, out[0].RequestID)
	assert.Equal(t, in.ApplicationRequestID, out[0].ApplicationRequestID)
	assert.Equal(t, in.PublicData, out[0].PublicData)
	assert.Equal(t, in.Ciphertexts, out[0].Ciphertexts)
	assert.Equal(t, in.CiphertextNames, out[0].CiphertextNames)
	assert.Equal(t, in.EnclaveEphemeralPublicKey, out[0].EnclaveEphemeralPublicKey)
	assert.Equal(t, in.MasterPublicKey, out[0].MasterPublicKey)
	assert.Equal(t, in.AppID, out[0].AppID)
	assert.Equal(t, in.Version, out[0].Version)
	assert.Equal(t, in.Signature, out[0].Signature)
}

func TestExecutionHelper_GetSecrets_NoDispatcherErrors(t *testing.T) {
	h := &enclaveExecutionHelper{
		remoteDispatcher: nil,
		logger:           logger.Test(t),
	}

	_, err := h.GetSecrets(context.Background(), &sdkpb.GetSecretsRequest{
		Requests: []*sdkpb.SecretRequest{{Id: "KEY", Namespace: "default"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote dispatcher is required")
}

func TestExecutionHelper_CallCapability_RemoteDispatch(t *testing.T) {
	mockDispatcher := &stubRemoteDispatcher{
		callCapabilityFn: func(_ context.Context, workflowID string, owner string, executionID string, orgID string, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
			require.Equal(t, "wf-123", workflowID)
			require.Equal(t, "0x0123456789abcDEF0123456789abCDef01234567", owner)
			require.Equal(t, "exec-123", executionID)
			require.Equal(t, "test-org", orgID, "orgID set on the helper must reach the dispatcher")
			return &sdkpb.CapabilityResponse{
				Response: &sdkpb.CapabilityResponse_Error{
					Error: "remote-dispatched:" + req.GetId(),
				},
			}, nil
		},
	}

	h := &enclaveExecutionHelper{
		remoteDispatcher: mockDispatcher,
		logger:           logger.Test(t),
		workflowID:       "wf-123",
		owner:            "0x0123456789abcDEF0123456789abCDef01234567",
		executionID:      "exec-123",
		orgID:            "test-org",
	}

	// Unknown capability with remote dispatcher should dispatch remotely.
	resp, err := h.CallCapability(context.Background(), &sdkpb.CapabilityRequest{
		Id:     "write_ethereum@1.0.0",
		Method: "Transmit",
	})
	require.NoError(t, err)
	assert.Equal(t, "remote-dispatched:write_ethereum@1.0.0", resp.GetError())
}

// --- Relay response verification edge cases (gateway->enclave hop) ---

func TestCallCapability_VerificationFailures(t *testing.T) {
	wantValue := wrapperspb.String("any")
	wantAny, err := anypb.New(wantValue)
	require.NoError(t, err)
	wantResp := &sdkpb.CapabilityResponse{Response: &sdkpb.CapabilityResponse_Payload{Payload: wantAny}}
	wantRespBytes, err := proto.Marshal(wantResp)
	require.NoError(t, err)
	makeResult := func() confidentialrelay.CapabilityResponseResult {
		return confidentialrelay.CapabilityResponseResult{
			Payload: base64.StdEncoding.EncodeToString(wantRespBytes),
		}
	}

	// The gateway is untrusted and the enclave verifies tolerantly: invalid,
	// foreign, duplicate, or sub-quorum signatures are skipped, not fatal. Every
	// case below therefore fails the same way — quorum is never reached — rather
	// than aborting on the first bad signature (the prior liveness gap).
	cases := []struct {
		name        string
		signers     int
		f           uint32
		mutate      func(t *testing.T, bundle *confidentialrelay.SignedCapabilityResponseBundle, params confidentialrelay.CapabilityRequestParams, signers []relaySigner)
		expectedErr string
	}{
		{
			name:    "hash mismatch — relay signed a different result",
			signers: 2,
			f:       1,
			mutate: func(_ *testing.T, bundle *confidentialrelay.SignedCapabilityResponseBundle, _ confidentialrelay.CapabilityRequestParams, _ []relaySigner) {
				// Tamper one response after signing: its recomputed hash will not
				// match its signature, dropping it below the F+1 valid threshold.
				bundle.Responses[0].Result.Payload = base64.StdEncoding.EncodeToString([]byte("tampered"))
			},
			expectedErr: "no relay-DON result reached quorum",
		},
		{
			name:    "unknown signer — signed by a key not in the configured set",
			signers: 2,
			f:       1,
			mutate: func(t *testing.T, bundle *confidentialrelay.SignedCapabilityResponseBundle, params confidentialrelay.CapabilityRequestParams, _ []relaySigner) {
				stranger := newRelaySigners(t, 1)[0]
				bundle.Responses[1] = oneSignedResponse(t, bundle.Responses[1].Result, params, stranger)
			},
			expectedErr: "no relay-DON result reached quorum",
		},
		{
			name:    "duplicate signer — same signer used twice",
			signers: 2,
			f:       1,
			mutate: func(t *testing.T, bundle *confidentialrelay.SignedCapabilityResponseBundle, params confidentialrelay.CapabilityRequestParams, signers []relaySigner) {
				// Both responses now carry signer[0]'s signature: only one distinct
				// valid signer, below the F+1=2 requirement.
				bundle.Responses[1] = oneSignedResponse(t, bundle.Responses[1].Result, params, signers[0])
			},
			expectedErr: "no relay-DON result reached quorum",
		},
		{
			name:    "sub-quorum — fewer responses than F+1",
			signers: 3,
			f:       2, // need 3 valid distinct signers
			mutate: func(_ *testing.T, bundle *confidentialrelay.SignedCapabilityResponseBundle, _ confidentialrelay.CapabilityRequestParams, _ []relaySigner) {
				bundle.Responses = bundle.Responses[:2]
			},
			expectedErr: "no relay-DON result reached quorum",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signers := newRelaySigners(t, tc.signers)
			srv := httptest.NewServer(jsonRPCHandler(t, func(_ string, params json.RawMessage) (any, error) {
				var p confidentialrelay.CapabilityRequestParams
				require.NoError(t, json.Unmarshal(params, &p))
				bundle := signCapabilityBundle(t, makeResult(), p, signers)
				tc.mutate(t, &bundle, p, signers)
				return bundle, nil
			}))
			defer srv.Close()

			d := NewRemoteDispatcher(
				gateway.NewGatewayClient(srv.URL, nil),
				nil,
				relayDONConfig(signers, tc.f),
				logger.Test(t),
				nil, nil,
				signatureverifier.NewEd25519SignatureVerifier(),
			)
			_, err := d.CallCapability(context.Background(), "wf-cap", "0x0123456789abcdef0123456789abcdef01234567", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", &sdkpb.CapabilityRequest{
				Id:         "write_ethereum@1.0.0",
				Method:     "Transmit",
				CallbackId: 17,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// A compromised relay node (or untrusted gateway) can stuff the bundle with extra
// responses carrying invalid or foreign signatures. As long as F+1 honest responses
// are present, the enclave must still reach quorum: noise cannot deny service.
func TestCallCapability_TolerantToNoise(t *testing.T) {
	signers := newRelaySigners(t, 2) // configured DON signer set, F=1 -> need 2 valid
	srv := httptest.NewServer(jsonRPCHandler(t, func(_ string, params json.RawMessage) (any, error) {
		var p confidentialrelay.CapabilityRequestParams
		require.NoError(t, json.Unmarshal(params, &p))
		result := capResultWithString(t, "ok")
		bundle := signCapabilityBundle(t, result, p, signers) // 2 valid responses
		// Noise: a foreign signer and a corrupted signature for the true result.
		stranger := newRelaySigners(t, 1)[0]
		bundle.Responses = append(bundle.Responses, oneSignedResponse(t, result, p, stranger))
		corrupt := oneSignedResponse(t, result, p, signers[0])
		corrupt.Signature.Signature = append([]byte(nil), corrupt.Signature.Signature...)
		corrupt.Signature.Signature[0] ^= 0xFF
		bundle.Responses = append(bundle.Responses, corrupt)
		return bundle, nil
	}))
	defer srv.Close()

	d := NewRemoteDispatcher(
		gateway.NewGatewayClient(srv.URL, nil),
		nil,
		relayDONConfig(signers, 1),
		logger.Test(t),
		nil, nil,
		signatureverifier.NewEd25519SignatureVerifier(),
	)
	resp, err := d.CallCapability(context.Background(), "wf-cap", "0x0123456789abcdef0123456789abcdef01234567", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", &sdkpb.CapabilityRequest{
		Id:         "write_ethereum@1.0.0",
		Method:     "Transmit",
		CallbackId: 17,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// A faulty in-set signer can sign a forged result, but honest nodes sign only the
// true result. The forged result therefore reaches at most F valid signers and can
// never win; the enclave returns the true result backed by F+1 honest signers.
func TestCallCapability_ForgedResultCannotWin(t *testing.T) {
	signers := newRelaySigners(t, 3) // F=1 -> need 2 valid distinct signers
	trueResult := capResultWithString(t, "true-value")
	forged := capResultWithString(t, "forged-value")

	srv := httptest.NewServer(jsonRPCHandler(t, func(_ string, params json.RawMessage) (any, error) {
		var p confidentialrelay.CapabilityRequestParams
		require.NoError(t, json.Unmarshal(params, &p))
		bundle := confidentialrelay.SignedCapabilityResponseBundle{
			Responses: []confidentialrelay.SignedCapabilityResponseResult{
				// Faulty node signs a forged result: only one valid signer for it.
				oneSignedResponse(t, forged, p, signers[0]),
				// Two honest nodes sign the true result -> quorum.
				oneSignedResponse(t, trueResult, p, signers[1]),
				oneSignedResponse(t, trueResult, p, signers[2]),
			},
		}
		return bundle, nil
	}))
	defer srv.Close()

	d := NewRemoteDispatcher(
		gateway.NewGatewayClient(srv.URL, nil),
		nil,
		relayDONConfig(signers, 1),
		logger.Test(t),
		nil, nil,
		signatureverifier.NewEd25519SignatureVerifier(),
	)
	resp, err := d.CallCapability(context.Background(), "wf-cap", "0x0123456789abcdef0123456789abcdef01234567", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", &sdkpb.CapabilityRequest{
		Id:         "write_ethereum@1.0.0",
		Method:     "Transmit",
		CallbackId: 17,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	payload := resp.GetPayload()
	require.NotNil(t, payload)
	var gotValue wrapperspb.StringValue
	require.NoError(t, anypb.UnmarshalTo(payload, &gotValue, proto.UnmarshalOptions{}))
	require.Equal(t, "true-value", gotValue.GetValue())
}

// --- Relay signer helpers ---

type relaySigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newRelaySigners(t *testing.T, n int) []relaySigner {
	t.Helper()
	signers := make([]relaySigner, n)
	for i := range signers {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signers[i] = relaySigner{pub: pub, priv: priv}
	}
	return signers
}

func (s relaySigner) sign(hash [32]byte) confidentialrelay.RelayResponseSignature {
	payload := confidentialrelay.RelayResponseSignaturePayload(hash)
	return confidentialrelay.RelayResponseSignature{
		Signer:    s.pub,
		Signature: ed25519.Sign(s.priv, payload),
	}
}

func relayDONConfig(signers []relaySigner, f uint32) types.EnclaveConfig {
	pubs := make([][]byte, len(signers))
	for i, s := range signers {
		pubs[i] = s.pub
	}
	// The same DON serves both workflow and relay roles, so we populate the
	// single EnclaveConfig.Signers/F that selectQuorumResult reads.
	// MasterPublicKey is non-empty so chainlink-common's confidentialrelay
	// Validate accepts the outgoing relay request; the value itself is not
	// asserted by the relay-DON signature path.
	return types.EnclaveConfig{
		Signers:         pubs,
		F:               f,
		MasterPublicKey: []byte("test-master-public-key"),
	}
}

// signCapabilityBundle mirrors the honest relay flow: each node returns its own
// per-node response carrying the same logical result and that node's single
// signature. The gateway forwards them as a bundle.
func signCapabilityBundle(
	t *testing.T,
	result confidentialrelay.CapabilityResponseResult,
	params confidentialrelay.CapabilityRequestParams,
	signers []relaySigner,
) confidentialrelay.SignedCapabilityResponseBundle {
	t.Helper()
	hash, err := result.Hash(params)
	require.NoError(t, err)
	resps := make([]confidentialrelay.SignedCapabilityResponseResult, len(signers))
	for i, s := range signers {
		resps[i] = confidentialrelay.SignedCapabilityResponseResult{Result: result, Signature: s.sign(hash)}
	}
	return confidentialrelay.SignedCapabilityResponseBundle{Responses: resps}
}

// oneSignedResponse builds a single per-node response (one node, one signature).
func oneSignedResponse(
	t *testing.T,
	result confidentialrelay.CapabilityResponseResult,
	params confidentialrelay.CapabilityRequestParams,
	signer relaySigner,
) confidentialrelay.SignedCapabilityResponseResult {
	t.Helper()
	hash, err := result.Hash(params)
	require.NoError(t, err)
	return confidentialrelay.SignedCapabilityResponseResult{Result: result, Signature: signer.sign(hash)}
}

// capResultWithString builds a CapabilityResponseResult whose Payload is a valid
// base64-encoded CapabilityResponse proto wrapping the given string, so the
// dispatcher's proto.Unmarshal of the winning result succeeds.
func capResultWithString(t *testing.T, s string) confidentialrelay.CapabilityResponseResult {
	t.Helper()
	anyVal, err := anypb.New(wrapperspb.String(s))
	require.NoError(t, err)
	resp := &sdkpb.CapabilityResponse{Response: &sdkpb.CapabilityResponse_Payload{Payload: anyVal}}
	b, err := proto.Marshal(resp)
	require.NoError(t, err)
	return confidentialrelay.CapabilityResponseResult{Payload: base64.StdEncoding.EncodeToString(b)}
}

// --- Test stubs ---

type stubRemoteDispatcher struct {
	callCapabilityFn   func(context.Context, string, string, string, string, *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error)
	getSecretsFn       func(context.Context, string, [32]byte, *sdkpb.GetSecretsRequest, string, string, string) ([]*sdkpb.SecretResponse, error)
	lastSignedRequests []types.SignedComputeRequest
}

func (s *stubRemoteDispatcher) CallCapability(ctx context.Context, workflowID string, owner string, executionID string, orgID string, req *sdkpb.CapabilityRequest) (*sdkpb.CapabilityResponse, error) {
	return s.callCapabilityFn(ctx, workflowID, owner, executionID, orgID, req)
}

func (s *stubRemoteDispatcher) SetConfig(_ types.EnclaveConfig) {}

func (s *stubRemoteDispatcher) GetSecrets(ctx context.Context, workflowID string, requestID [32]byte, req *sdkpb.GetSecretsRequest, owner string, executionID string, orgID string, signedRequests []types.SignedComputeRequest) ([]*sdkpb.SecretResponse, error) {
	s.lastSignedRequests = signedRequests
	if s.getSecretsFn != nil {
		return s.getSecretsFn(ctx, workflowID, requestID, req, owner, executionID, orgID)
	}
	return nil, nil
}

// TestCallCapability_PopulatesEnclaveConfig covers the PRIV-458 follow-up:
// the dispatcher must fill EnclaveConfig on every outgoing relay request so
// the relay-DON handler can compare it against onchain DON state before
// treating an attested request as trusted.
func TestCallCapability_PopulatesEnclaveConfig(t *testing.T) {
	signers := newRelaySigners(t, 2)
	wantCfg := relayDONConfig(signers, 1)
	wantCfg.T = 3

	wantResp := &sdkpb.CapabilityResponse{
		Response: &sdkpb.CapabilityResponse_Payload{Payload: nil},
	}
	wantRespBytes, err := proto.Marshal(wantResp)
	require.NoError(t, err)

	var received confidentialrelay.CapabilityRequestParams
	srv := httptest.NewServer(jsonRPCHandler(t, func(method string, params json.RawMessage) (any, error) {
		require.Equal(t, confidentialrelay.MethodCapabilityExec, method)
		require.NoError(t, json.Unmarshal(params, &received))
		result := confidentialrelay.CapabilityResponseResult{
			Payload: base64.StdEncoding.EncodeToString(wantRespBytes),
		}
		return signCapabilityBundle(t, result, received, signers), nil
	}))
	defer srv.Close()

	d := NewRemoteDispatcher(
		gateway.NewGatewayClient(srv.URL, nil),
		nil,
		wantCfg,
		logger.Test(t),
		nil, nil,
		signatureverifier.NewEd25519SignatureVerifier(),
	)

	_, err = d.CallCapability(context.Background(), "wf-cfg", "0xowner", "0000000000000000000000000000000000000000000000000000000000000001", "", &sdkpb.CapabilityRequest{
		Id:         "write_ethereum@1.0.0",
		Method:     "Transmit",
		CallbackId: 1,
	})
	require.NoError(t, err)

	assert.Equal(t, wantCfg.MasterPublicKey, received.EnclaveConfig.MasterPublicKey)
	assert.Equal(t, wantCfg.T, received.EnclaveConfig.T)
	assert.Equal(t, wantCfg.F, received.EnclaveConfig.F)
	require.Equal(t, len(wantCfg.Signers), len(received.EnclaveConfig.Signers))
	for i := range wantCfg.Signers {
		assert.Equal(t, wantCfg.Signers[i], received.EnclaveConfig.Signers[i])
	}
}

// TestCallCapability_SetConfigUpdatesOutgoingConfig covers that a SetConfig
// call between two outgoing requests is reflected in the second request's
// EnclaveConfig. Without this, a config rotation after dispatcher
// construction would silently keep sending the original config.
//
// Signers stay the same across both configs so the mock relay's response
// signatures continue to verify; T is what we flip between calls to prove
// the propagation works.
func TestCallCapability_SetConfigUpdatesOutgoingConfig(t *testing.T) {
	signers := newRelaySigners(t, 2)
	initial := relayDONConfig(signers, 1)
	initial.T = 1
	updated := relayDONConfig(signers, 1)
	updated.T = 2
	updated.MasterPublicKey = []byte("updated-mpk")

	wantResp := &sdkpb.CapabilityResponse{Response: &sdkpb.CapabilityResponse_Payload{Payload: nil}}
	wantRespBytes, err := proto.Marshal(wantResp)
	require.NoError(t, err)

	var lastReceived confidentialrelay.CapabilityRequestParams
	srv := httptest.NewServer(jsonRPCHandler(t, func(_ string, params json.RawMessage) (any, error) {
		require.NoError(t, json.Unmarshal(params, &lastReceived))
		result := confidentialrelay.CapabilityResponseResult{
			Payload: base64.StdEncoding.EncodeToString(wantRespBytes),
		}
		return signCapabilityBundle(t, result, lastReceived, signers), nil
	}))
	defer srv.Close()

	d := NewRemoteDispatcher(
		gateway.NewGatewayClient(srv.URL, nil),
		nil,
		initial,
		logger.Test(t),
		nil, nil,
		signatureverifier.NewEd25519SignatureVerifier(),
	)

	call := func() {
		_, err := d.CallCapability(context.Background(), "wf-cfg", "0xowner", "0000000000000000000000000000000000000000000000000000000000000001", "", &sdkpb.CapabilityRequest{
			Id:         "write_ethereum@1.0.0",
			CallbackId: 1,
		})
		require.NoError(t, err)
	}

	call()
	assert.Equal(t, initial.MasterPublicKey, lastReceived.EnclaveConfig.MasterPublicKey)
	assert.Equal(t, initial.T, lastReceived.EnclaveConfig.T)

	d.SetConfig(updated)
	call()
	assert.Equal(t, updated.MasterPublicKey, lastReceived.EnclaveConfig.MasterPublicKey)
	assert.Equal(t, updated.T, lastReceived.EnclaveConfig.T)
}

// TestOrderRelaySecrets covers PRIV-468 / CL112-16: the relay's secrets are
// validated against the request and rebuilt in request order, so a reordered,
// padded, duplicated, or trimmed response cannot mis-deliver to positional
// consumers.
func TestOrderRelaySecrets(t *testing.T) {
	id := func(ns, k string) confidentialrelay.SecretIdentifier {
		return confidentialrelay.SecretIdentifier{Namespace: ns, Key: k}
	}
	entry := func(ns, k string) confidentialrelay.SecretEntry {
		return confidentialrelay.SecretEntry{ID: id(ns, k), Ciphertext: k}
	}
	req := []confidentialrelay.SecretIdentifier{id("main", "a"), id("main", "b")}

	t.Run("reordered response restored to request order", func(t *testing.T) {
		ordered, err := orderRelaySecrets(req, []confidentialrelay.SecretEntry{entry("main", "b"), entry("main", "a")})
		require.NoError(t, err)
		require.Len(t, ordered, 2)
		assert.Equal(t, "a", ordered[0].id.Key)
		assert.Equal(t, "b", ordered[1].id.Key)
		require.NotNil(t, ordered[0].entry)
		assert.Equal(t, "a", ordered[0].entry.ID.Key)
		require.NotNil(t, ordered[1].entry)
		assert.Equal(t, "b", ordered[1].entry.ID.Key)
	})

	t.Run("unexpected id rejected", func(t *testing.T) {
		_, err := orderRelaySecrets(req, []confidentialrelay.SecretEntry{entry("main", "a"), entry("main", "x")})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected secret")
	})

	t.Run("duplicate id rejected", func(t *testing.T) {
		_, err := orderRelaySecrets(req, []confidentialrelay.SecretEntry{entry("main", "a"), entry("main", "a")})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate secret")
	})

	t.Run("omitted secret yields nil entry in its slot", func(t *testing.T) {
		ordered, err := orderRelaySecrets(req, []confidentialrelay.SecretEntry{entry("main", "a")})
		require.NoError(t, err)
		require.Len(t, ordered, 2)
		require.NotNil(t, ordered[0].entry)
		assert.Nil(t, ordered[1].entry)
		assert.Equal(t, "b", ordered[1].id.Key)
	})
}
