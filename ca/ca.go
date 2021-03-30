package ca

import (
	/*"fmt"
	"bytes"
	"encoding/json"
	"net/http"

	*/

	"sync"
	"time"
	"fmt"

	"github.com/golang/glog"
	"github.com/Workiva/go-datastructures/bitarray"
	"github.com/google/certificate-transparency-go/tls"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/signature"
	ctca "github.com/n-ct/ct-certificate-authority"
)

type CA struct {
	LogURLMap map[string] string // Maybe just have this be map[log]logURL
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

func (c *CA) DoRevocationTransparencyTasks(revType string) error {
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
		return fmt.Errorf("failed to create SRD at new MMD: %v", err)
	}
	glog.Infoln(srd)	

	// Store the SRD
	c.AddCASRD(srd)

	// Send SRD to Logger
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
	newMMDTimestamp := uint64(time.Now().Unix())
	c.PreviousMMDTimestamp = newMMDTimestamp - c.MMD
	return nil
}

// Make a post request to corresponding GossiperURL with the given ctObject
/*func (m *CA) Gossip(ctObject *mtr.CTObject) error {
	jsonBytes, err := json.Marshal(ctObject)	// Just use serialize method somewhere else
	if err != nil {
		return fmt.Errorf("failed to marshal %s ctobject when gossiping: %v", ctObject.TypeID, err)
	}
	gossipURL := utils.CreateRequestURL(m.GossiperURL, "/ct/v1/gossip")
	glog.Infof("\ngossip CTObject using Gossiper at address: %s", gossipURL)

	// Create request
	req, err := http.NewRequest("POST", gossipURL, bytes.NewBuffer(jsonBytes)) 
	req.Header.Set("X-Custom-Header", "myvalue");
	req.Header.Set("Content-Type", "application/json");

	// Send request
	client := &http.Client{};
	resp, err := client.Do(req);
	if err != nil {
		panic(err);
	}

	defer resp.Body.Close();
	return nil
}
*/