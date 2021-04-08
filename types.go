package ctca

import (
	mtr "github.com/n-ct/ct-monitor"
)

// Endpoint path const variables
const (
	GetRevocationStatusPath 	= "/ct/v1/get-revocation-status"
	PostLogSRDWithRevDataPath	= "/ct/v1/post-log-srd-with-rev-data"	
	PostNewRevocationNumsPath	= "/ct/v1/post-new-revocation-nums"
	RevokeAndProduceSRDPath		= "/ct/v1/revoke-and-produce-srd"
)

// TypeID const variables
const (
)

type RevocationStatus struct {
	CASRD 	mtr.CTObject
	LogSRDs	[]mtr.CTObject
}

type PostNewRevocationNumsRequest struct {
	RevocationNums []uint64
}

type RevokeAndProduceSRDRequest struct {
	PercentRevoked 	uint8
	TotalCerts 		uint64
}