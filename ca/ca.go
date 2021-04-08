package ca

import (
	"sync"
	"time"
	"fmt"
	"math"
	"math/rand"
	"bytes"
	"net/http"

	"github.com/golang/glog"
	"github.com/Workiva/go-datastructures/bitarray"
	"github.com/google/certificate-transparency-go/tls"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/signature"
	"github.com/n-ct/ct-monitor/entitylist"
	"github.com/n-ct/ct-monitor/utils"
	ctca "github.com/n-ct/ct-certificate-authority"
)

type CA struct {
	LogInfoMap map[string] *entitylist.LogInfo  // Maybe just have this be map[log]logURL
	RevocationObjMap map[string] *bitarray.BitArray
	CASignedDigestMap map[string]map[uint64] *mtr.SRDWithRevData
	LogSignedDigestMap map[string]map[uint64]map[string] *mtr.SRDWithRevData
	DeltaRevocations map[uint64]bool // Stores the delta revocations per mmd. Reset at the end of mmd and acts like a set
	ListenAddress string 
	MMD	uint64
	CAID string
	Signer *signature.Signer
	PreviousMMDTimestamp uint64
	sync.RWMutex // Mutex lock to prevent race conditions
}

// Create a new CA using the createCA function found in ca_setup.go
func NewCA(caConfigName string, caListName string, logListName string) (*CA, error){
	return createCA(caConfigName, caListName, logListName)
}

func (c *CA) AddRevocationNums(newRevocationNums *[]uint64) error {
	c.Lock()
	for _, num := range *newRevocationNums {
		c.DeltaRevocations[num] = true
	}
	c.Unlock()
	return nil
}

func (c *CA) AddCASRD(srdWithRevData *mtr.SRDWithRevData) (error) {
	c.Lock()
	revType := srdWithRevData.RevData.RevocationType
	timestamp := srdWithRevData.RevData.Timestamp
	if _, ok := c.CASignedDigestMap[revType]; !ok {
		c.CASignedDigestMap[revType] = make(map[uint64] *mtr.SRDWithRevData)
	}
	c.CASignedDigestMap[revType][timestamp] = srdWithRevData
	c.Unlock()
	return nil
}

func (c *CA) GetCASRD(revType string, timestamp uint64) (*mtr.SRDWithRevData, error) {
	var caSRD *mtr.SRDWithRevData
	c.RLock()
	if _, ok := c.CASignedDigestMap[revType]; !ok {
		return nil, fmt.Errorf("failed to find revType (%v) in caSRD map", revType)
	}
	if _, ok := c.CASignedDigestMap[revType][timestamp]; !ok {
		return nil, fmt.Errorf("failed to find timestamp (%v) in caSRD map", timestamp)
	}
	caSRD = c.CASignedDigestMap[revType][timestamp]
	c.RUnlock()
	return caSRD, nil
}

func (c *CA) AddLogSRD(srdWithRevData *mtr.SRDWithRevData) (error) {
	c.Lock()
	revType := srdWithRevData.RevData.RevocationType
	timestamp := srdWithRevData.RevData.Timestamp
	logID := srdWithRevData.SRD.EntityID
	if _, ok := c.LogSignedDigestMap[revType]; !ok {
		c.LogSignedDigestMap[revType] = make(map[uint64]map[string] *mtr.SRDWithRevData)
	}
	if _, ok := c.LogSignedDigestMap[revType][timestamp]; !ok {
		c.LogSignedDigestMap[revType][timestamp] = make(map[string] *mtr.SRDWithRevData)
	}
	c.LogSignedDigestMap[revType][timestamp][logID] = srdWithRevData
	c.Unlock()
	return nil
}

func (c *CA) GetLogSRD(revType string, timestamp uint64, logID string) (*mtr.SRDWithRevData, error) {
	var logSRD *mtr.SRDWithRevData
	c.RLock()
	if _, ok := c.LogSignedDigestMap[revType]; !ok {
		return nil, fmt.Errorf("failed to find revType (%v) in caSRD map", revType)
	}
	if _, ok := c.LogSignedDigestMap[revType][timestamp]; !ok {
		return nil, fmt.Errorf("failed to find timestamp (%v) in caSRD map", timestamp)
	}
	if _, ok := c.LogSignedDigestMap[revType][timestamp][logID]; !ok {
		return nil, fmt.Errorf("failed to find logID (%v) in caSRD map", logID)
	}
	logSRD = c.LogSignedDigestMap[revType][timestamp][logID]
	c.RUnlock()
	return logSRD, nil
}

func (c *CA) GetRecentLogSRDCTObjecList(revType string, timestamp uint64) ([]mtr.CTObject, error) {
	var logSRDs []mtr.CTObject
	c.RLock()
	if _, ok := c.LogSignedDigestMap[revType]; !ok {
		return nil, fmt.Errorf("failed to find revType (%v) in caSRD map", revType)
	}
	if _, ok := c.LogSignedDigestMap[revType][timestamp]; !ok {
		return nil, fmt.Errorf("failed to find timestamp (%v) in caSRD map", timestamp)
	}
	for _, v := range c.LogSignedDigestMap[revType][timestamp] {
		logSRDCTObj, err := mtr.ConstructCTObject(v)
		if err != nil {
			return nil, fmt.Errorf("failed to construct SRDCTObject: %w", err)
		}
		logSRDs = append(logSRDs, *logSRDCTObj)
	}
	c.RUnlock()
	return logSRDs, nil
}

func (c *CA) ClearDeltaRevocations() error {
	c.Lock()
	c.DeltaRevocations = make(map[uint64]bool)
	c.Unlock()
	return nil
}

func (c *CA) DeltaRevocationsToList() []uint64 {
	revList := []uint64{}
	for revNum := range c.DeltaRevocations {
		revList = append(revList, revNum)
	}
	return revList
}

// THIS IS A STRICTLY A METHOD USED FOR COLLECTING DATA 
func (c *CA) RevokeAndProduceSRD(totalCerts uint64, percentRevoked uint8) (*mtr.SRDWithRevData, error) {
	c.UpdateMMD()
	numToRevoke := uint64(math.Floor(float64(totalCerts) * float64(percentRevoked) / 100))
	revokedMap := make(map[uint64]bool)
	revNumList := []uint64{}
	for numToRevoke > 0 {
		newNumToRevoke := uint64(rand.Intn(int(totalCerts)))
		if _, ok := revokedMap[newNumToRevoke]; !ok {
			revokedMap[newNumToRevoke] =  true
			revNumList = append(revNumList, newNumToRevoke)
			numToRevoke -= 1
		}
	}
	c.AddRevocationNums(&revNumList)
	revType := "Let's-Revoke"
	srd, err := c.createNewMMDSRD(revType)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRD at new MMD: %v", err)
	}
	return srd, nil
}

func (c *CA) createNewMMDSRD(revType string) (*mtr.SRDWithRevData, error) {
	deltaRevList := c.DeltaRevocationsToList()
	crvDelta := ctca.GetCRVDelta(deltaRevList)
	currCRV, ok := c.RevocationObjMap[revType]
	if !ok {
		currCRV = ctca.CreateCRV([]uint64{}, 0)
	}
	newCRV := ctca.ApplyCRVDeltaToCRV(currCRV, crvDelta)
	c.RevocationObjMap[revType] = newCRV

	// Create SRD
	srd, err := CreateSRDWithRevData(newCRV, crvDelta, c.PreviousMMDTimestamp, c.CAID, tls.SHA256, c.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRD at new MMD: %v", err)
	}
	return srd, nil
}

func (c *CA) DoRevocationTransparencyTasks(revType string) error {
	srd, err := c.createNewMMDSRD(revType)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	// Store the SRD
	c.AddCASRD(srd)

	// Send SRD to Logger
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	// UNCOMMENT THE POSTCASRD
	//PostCASRD(srd)	
	return nil
}

func CreateSRDWithRevData(crv, deltaCRV *bitarray.BitArray, timestamp uint64, entityID string, hashAlgo tls.HashAlgorithm, signer *signature.Signer) (*mtr.SRDWithRevData, error) {
	revData, err := createRevocationData(deltaCRV, timestamp, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed SRDWithRevData creation: %w", err)
	}
	srd, err := createSRD(crv, deltaCRV, timestamp, entityID, hashAlgo, signer)
	if err != nil {
		return nil, fmt.Errorf("failed SRDWithRevData creation: %w", err)
	}
	srdWithRevData := &mtr.SRDWithRevData{
		RevData: *revData,
		SRD: *srd,
	}
	return srdWithRevData, nil
}

func createSRD(crv, deltaCRV *bitarray.BitArray, timestamp uint64, entityID string, hashAlgo tls.HashAlgorithm, signer *signature.Signer) (*mtr.SignedRevocationDigest, error) {
	revDigest, err := createRevocationDigest(crv, deltaCRV, timestamp, hashAlgo)	
	if err != nil {
		return nil, fmt.Errorf("failed to compress crv when creating rev digest: %v", err)
	}
	sig, err := signer.CreateSignature(hashAlgo, revDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign revDigest when creating srd: %v", err)
	}
	srd := &mtr.SignedRevocationDigest {
		EntityID: entityID,
		RevDigest: *revDigest,
		Signature: *sig,
	}
	return srd, nil
}

func createRevocationDigest(crv, deltaCRV *bitarray.BitArray, timestamp uint64, hashAlgo tls.HashAlgorithm) (*mtr.RevocationDigest, error) {
	compCRV, err := ctca.CompressCRV(crv)
	if err != nil {
		return nil, fmt.Errorf("failed to compress crv when creating rev digest: %w", err)
	}
	crvHash, _, err := signature.GenerateHash(hashAlgo, compCRV)
	if err != nil {
		return nil, fmt.Errorf("failed to hash crv when creating rev digest: %w", err)
	}

	compDeltaCRV, err := ctca.CompressCRV(deltaCRV)
	if err != nil {
		return nil, fmt.Errorf("failed to compress deltaCRV when creating rev digest: %w", err)
	}
	crvDeltaHash, _, err := signature.GenerateHash(hashAlgo, compDeltaCRV)
	if err != nil {
		return nil, fmt.Errorf("failed to hash deltaCRV when creating rev digest: %w", err)
	}

	revDigest := &mtr.RevocationDigest{
		Timestamp: timestamp, 
		CRVHash: crvHash, 
		CRVDeltaHash: crvDeltaHash,
	}
	return revDigest, nil
}

func createRevocationData(deltaCRV *bitarray.BitArray, timestamp uint64, entityID string) (*mtr.RevocationData, error) {
	revType := "Let's-Revoke"
	compDeltaCRV, err := ctca.CompressCRV(deltaCRV)
	if err != nil {
		return nil, fmt.Errorf("failed to compress deltaCRV when creating rev data: %w", err)
	}

	revData := &mtr.RevocationData{
		EntityID: entityID,
		RevocationType: revType,
		Timestamp: timestamp,
		CRVDelta: compDeltaCRV,
	}
	return revData, nil
}

func (c *CA) UpdateMMD() error {
	var newMMDTimestamp uint64
	if c.PreviousMMDTimestamp == 0 {
		newMMDTimestamp = uint64(time.Now().Unix())
	} else {
		newMMDTimestamp = c.PreviousMMDTimestamp +  (2 * c.MMD)
	}
	c.PreviousMMDTimestamp = newMMDTimestamp - c.MMD
	return nil
}

// Make a post request to LogURLs with the given srd
func (c *CA) PostCASRD(srd *mtr.SRDWithRevData) error {
	jsonBytes, err := signature.SerializeData(*srd)	// Just use serialize method somewhere else
	if err != nil {
		return fmt.Errorf("failed to marshal SRDWithRevData (%v) when sending post to log: %v", srd, err)
	}
	for _, logInfo := range c.LogInfoMap {
		logURL := logInfo.URL
		logPostURL := utils.CreateRequestURL(logURL, "/ct/v1/post-ca-srd")
		glog.Infof("\ngossip CTObject using Gossiper at address: %s", logPostURL)

		// Create request
		req, err := http.NewRequest("POST", logPostURL, bytes.NewBuffer(jsonBytes)) 
		req.Header.Set("X-Custom-Header", "myvalue");
		req.Header.Set("Content-Type", "application/json");

		// Send request
		client := &http.Client{};
		resp, err := client.Do(req);
		if err != nil {
			panic(err);
		}

		defer resp.Body.Close();
	}

	return nil
}

func (c *CA) VerifyLogSRDSignature(srd *mtr.SignedRevocationDigest) error {
	logID := srd.EntityID
	logInfo, ok := c.LogInfoMap[logID]
	if !ok {
		return fmt.Errorf("logID (%v) not found in logInfoMap", logID)
	}
	logKey := logInfo.Key	
	return VerifySRDSignature(srd, logKey)
}

func VerifySRDSignature(srd *mtr.SignedRevocationDigest, key string) error {
	return signature.VerifySignature(key, srd.RevDigest, srd.Signature)
}

func (c *CA) GetLatestRevocationStatus() (*ctca.RevocationStatus, error) {
	latestTimestamp := c.PreviousMMDTimestamp - c.MMD
	revType := "Let's-Revoke"
	caSRD, err := c.GetCASRD(revType, latestTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to get CASRD for revocationStatus: %w", err)
	}
	caSRDCTObj, err := mtr.ConstructCTObject(caSRD)
	if err != nil {
		return nil, fmt.Errorf("failed to construct CASRDCTObject: %w", err)
	}
	logSRDs, err := c.GetRecentLogSRDCTObjecList(revType, latestTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to get logSRDs for revocationStatus: %w", err)
	}
	revocationStatus := &ctca.RevocationStatus{
		CASRD: *caSRDCTObj, 
		LogSRDs: logSRDs,
	}
	return revocationStatus, nil
}