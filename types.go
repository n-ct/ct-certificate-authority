package ctca

import (
	ct "github.com/google/certificate-transparency-go"
)

// Endpoint path const variables
const (
	GetRevocationStatusPath 	= "/ct/v1/get-revocation-status"
	PostLogRevocationDigestPath	= "/ct/v1/post-log-revocation-digest"	
)

// TypeID const variables
const (
)

type RevData struct {
	RevType 	string
	Timestamp 	uint64
	CRVDelta	[]byte	// CRVDelta will always be compressed
}

type RevDigest struct {
	Timestamp 	 uint64
	CRVHash		 []byte
	CRVDeltaHash []byte
}

type SignedRevDigest struct {
	Signer 				string
	RevocationDigest	RevDigest	
	Signature			ct.DigitallySigned
}