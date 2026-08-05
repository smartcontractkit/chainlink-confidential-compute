package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialrelay"
	sdkpb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// maxDiagFieldLen bounds a single free-form string copied into relay diagnostics.
const maxDiagFieldLen = 160

// maxDiagLen bounds the joined per-entry diagnostics in a quorum error, which is
// returned to the workflow and logged.
const maxDiagLen = 4096

// canonicalCapabilityPayload returns the payload rewritten into the form used for
// quorum grouping. changed is false for payloads that need no rewrite, in which
// case the returned payload is empty.
//
// Only consensus report payloads are rewritten, and the rewrite drops the report's
// attributed OCR signatures. A relay node collects those itself, so the same
// logical report arrives from each node carrying a different subset in a different
// order and the raw payloads never hash alike. Excluding them leaves the report
// body — config digest, sequence number, report context, raw report — as what the
// nodes are polled for agreement on.
//
// Grouping on this form is safe because the relay signature is still verified
// against the hash of the result exactly as the node sent it: canonicalization only
// decides which responses are counted as agreeing, never whether a response is
// authentic.
func canonicalCapabilityPayload(payload string) (canonical string, changed bool, err error) {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", false, fmt.Errorf("decoding payload: %w", err)
	}
	resp := &sdkpb.CapabilityResponse{}
	if err := proto.Unmarshal(raw, resp); err != nil {
		return "", false, fmt.Errorf("unmarshalling capability response: %w", err)
	}
	inner := resp.GetPayload()
	if inner == nil || !inner.MessageIs((*sdkpb.ReportResponse)(nil)) {
		return "", false, nil
	}

	report := &sdkpb.ReportResponse{}
	if err := inner.UnmarshalTo(report); err != nil {
		return "", false, fmt.Errorf("unmarshalling report response: %w", err)
	}
	report.Sigs = nil

	wrapped := &anypb.Any{}
	if err := anypb.MarshalFrom(wrapped, report, proto.MarshalOptions{Deterministic: true}); err != nil {
		return "", false, fmt.Errorf("marshalling report response: %w", err)
	}
	out := &sdkpb.CapabilityResponse{Response: &sdkpb.CapabilityResponse_Payload{Payload: wrapped}}
	outBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(out)
	if err != nil {
		return "", false, fmt.Errorf("marshalling capability response: %w", err)
	}
	return base64.StdEncoding.EncodeToString(outBytes), true, nil
}

// describeCapabilityResult renders one relay capability response for the quorum
// diagnostics: the decoded fields of a consensus report when that is what the
// payload holds, otherwise the payload's type, size and digest. Payload bodies
// are reduced to digests rather than reproduced, since a capability response can
// carry user data.
func describeCapabilityResult(result confidentialrelay.CapabilityResponseResult) string {
	parts := make([]string, 0, 8)
	if result.Error != "" {
		parts = append(parts, fmt.Sprintf("resultError=%q", truncateDiag(result.Error)))
	}

	raw, err := base64.StdEncoding.DecodeString(result.Payload)
	if err != nil {
		return join(append(parts, fmt.Sprintf("payload=undecodable(%v)", err)))
	}
	parts = append(parts, fmt.Sprintf("payload=%dB/%s", len(raw), digestOf(raw)))
	if len(raw) == 0 {
		return join(parts)
	}

	resp := &sdkpb.CapabilityResponse{}
	if err := proto.Unmarshal(raw, resp); err != nil {
		return join(append(parts, fmt.Sprintf("payload=unparseable(%v)", err)))
	}
	if respErr := resp.GetError(); respErr != "" {
		parts = append(parts, fmt.Sprintf("responseError=%q", truncateDiag(respErr)))
	}
	inner := resp.GetPayload()
	if inner == nil {
		return join(parts)
	}
	parts = append(parts, "type="+shortTypeURL(inner.GetTypeUrl()))

	if !inner.MessageIs((*sdkpb.ReportResponse)(nil)) {
		return join(parts)
	}
	report := &sdkpb.ReportResponse{}
	if err := inner.UnmarshalTo(report); err != nil {
		return join(append(parts, fmt.Sprintf("report=unparseable(%v)", err)))
	}
	sigs := make([]string, 0, len(report.GetSigs()))
	for _, s := range report.GetSigs() {
		sigs = append(sigs, fmt.Sprintf("%d/%s", s.GetSignerId(), digestOf(s.GetSignature())))
	}
	return join(append(parts,
		fmt.Sprintf("configDigest=%s", digestOf(report.GetConfigDigest())),
		fmt.Sprintf("seqNr=%d", report.GetSeqNr()),
		fmt.Sprintf("reportContext=%s", digestOf(report.GetReportContext())),
		fmt.Sprintf("rawReport=%dB/%s", len(report.GetRawReport()), digestOf(report.GetRawReport())),
		fmt.Sprintf("sigs=%d[%s]", len(report.GetSigs()), strings.Join(sigs, ",")),
	))
}

// describeSecretsResult renders one relay secrets response for the quorum
// diagnostics. Secret identifiers are included; ciphertexts and encrypted shares
// are reduced to digests and counts so nothing recoverable reaches a log.
func describeSecretsResult(result confidentialrelay.SecretsResponseResult) string {
	entries := make([]string, 0, len(result.Secrets))
	for _, s := range result.Secrets {
		entries = append(entries, fmt.Sprintf("%s/%s:ct=%s,shares=%d",
			s.ID.Namespace, s.ID.Key, digestOf([]byte(s.Ciphertext)), len(s.EncryptedShares)))
	}
	return fmt.Sprintf("secrets=%d[%s]", len(result.Secrets), strings.Join(entries, " "))
}

// digestOf renders a short SHA-256 prefix for comparing values across responses
// without reproducing them.
func digestOf(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:4])
}

// shortHash renders a hash prefix for identifying a result group in diagnostics.
func shortHash(h [32]byte) string {
	return hex.EncodeToString(h[:4])
}

// shortBytes renders a signer key prefix for diagnostics.
func shortBytes(b []byte) string {
	if len(b) == 0 {
		return "none"
	}
	if len(b) > 8 {
		b = b[:8]
	}
	return hex.EncodeToString(b)
}

// shortTypeURL trims the leading host of a protobuf Any type URL.
func shortTypeURL(url string) string {
	if i := strings.LastIndex(url, "/"); i >= 0 {
		return url[i+1:]
	}
	return url
}

func truncateDiag(s string) string {
	return truncate(s, maxDiagFieldLen)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...truncated"
}

func join(parts []string) string {
	return strings.Join(parts, " ")
}
