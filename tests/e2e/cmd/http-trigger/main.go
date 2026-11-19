package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	jsonrpc "github.com/smartcontractkit/chainlink-common/pkg/jsonrpc2"
	"github.com/smartcontractkit/chainlink-common/pkg/types/gateway"
	chainlinkutils "github.com/smartcontractkit/chainlink/v2/core/utils"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("http-trigger", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyFile := flags.String("key-file", "", "disposable signing key file")
	initKey := flags.Bool("init-key", false, "create the key file and print only its EVM address")
	endpoint := flags.String("gateway", "", "approved staging HTTP-trigger HTTPS endpoint")
	workflowID := flags.String("workflow-id", "", "deployed workflow ID")
	caseName := flags.String("case", "", "redaction smoke case: redirect or certificate")
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid arguments: use -key-file with either -init-key or -gateway, -workflow-id and -case")
	}
	if flags.NArg() != 0 || *keyFile == "" {
		return errors.New("-key-file is required; positional arguments are not supported")
	}
	if *initKey {
		if *endpoint != "" || *workflowID != "" || *caseName != "" {
			return errors.New("-init-key cannot send a trigger")
		}
		address, err := createKey(*keyFile)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, address)
		return err
	}
	key, err := crypto.LoadECDSA(*keyFile)
	if err != nil {
		return errors.New("cannot load signing key file")
	}
	result, err := sendTrigger(context.Background(), *endpoint, *workflowID, *caseName, key, nil)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

func createKey(path string) (string, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return "", errors.New("cannot generate signing key")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("cannot create signing key file (must not already exist)")
	}
	_, writeErr := file.WriteString(hex.EncodeToString(crypto.FromECDSA(key)))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return "", errors.New("cannot write signing key file")
	}
	return strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex()), nil
}

func sendTrigger(ctx context.Context, endpoint, workflowID, caseName string, key *ecdsa.PrivateKey, transport http.RoundTripper) (*gateway.HTTPTriggerResponse, error) {
	if caseName != "redirect" && caseName != "certificate" {
		return nil, errors.New("case must be redirect or certificate")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("gateway must be an HTTPS URL without credentials, query or fragment")
	}
	workflowID = strings.ToLower(strings.TrimPrefix(workflowID, "0x"))
	id, err := hex.DecodeString(workflowID)
	if err != nil || len(id) != 32 {
		return nil, errors.New("workflow ID must be 32 bytes of hex")
	}
	input, _ := json.Marshal(map[string]string{"case": caseName})
	params := gateway.HTTPTriggerRequest{
		Workflow: gateway.WorkflowSelector{WorkflowID: workflowID},
		Input:    input,
	}
	req := jsonrpc.Request[gateway.HTTPTriggerRequest]{
		Version: jsonrpc.JsonRpcVersion, ID: uuid.NewString(),
		Method: gateway.MethodWorkflowExecute, Params: &params,
	}
	token, err := chainlinkutils.CreateRequestJWT(req)
	if err != nil {
		return nil, errors.New("cannot create trigger JWT")
	}
	req.Auth, err = token.SignedString(key)
	if err != nil {
		return nil, errors.New("cannot sign trigger JWT")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.New("cannot encode trigger request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot create trigger request")
	}
	request.Header.Set("Content-Type", "application/jsonrpc")
	request.Header.Set("Accept", "application/json")
	// A redirect must not forward the signed request; an uncertain result must not be retried automatically.
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(request)
	if err != nil {
		return nil, errors.New("trigger transport failed; check execution history before retrying")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned HTTP %d; check execution history before retrying", resp.StatusCode)
	}
	var reply jsonrpc.Response[gateway.HTTPTriggerResponse]
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&reply); err != nil {
		return nil, errors.New("invalid gateway response; check execution history before retrying")
	}
	if reply.Version != jsonrpc.JsonRpcVersion || reply.ID != req.ID || reply.Error != nil || reply.Result == nil || reply.Result.Status != gateway.HTTPTriggerStatusAccepted {
		return nil, errors.New("gateway did not confirm acceptance; check execution history before retrying")
	}
	return reply.Result, nil
}
