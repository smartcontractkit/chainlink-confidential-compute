package types

import (
	peeridhelper "github.com/smartcontractkit/chainlink-confidential-compute/types/copied/libocr"
)

func MakePeerIDSignatureDomainSeparatedPayload(domainSeparator string, message []byte) []byte {
	return peeridhelper.MakePeerIDSignatureDomainSeparatedPayload(domainSeparator, message)
}
