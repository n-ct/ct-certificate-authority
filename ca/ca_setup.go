package ca

import (
	"fmt"
	"strings"
	"encoding/json"

	"github.com/Workiva/go-datastructures/bitarray"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/entitylist"
	"github.com/n-ct/ct-monitor/utils"
	"github.com/n-ct/ct-monitor/signature"
)

// Create CA 
func createCA(caConfigName string, caListName string, logListName string) (*CA, error){
	caConfig, err := parseCAConfig(caConfigName)
	if nil != err {
		return nil, fmt.Errorf("failed to setup new ca: %w", err)
	}
	logInfoMap, err := createLogInfoMap(caConfig, logListName)
	if nil != err {
		return nil, fmt.Errorf("failed to setup new ca: %w", err)
	}
	signer, err := createSigner(caConfig)
	if nil != err {
		return nil, fmt.Errorf("failed to setup new ca: %w", err)
	}
	caURL, mmd, caID, err := getCAListInfo(caListName, caConfig)
	if nil != err {
		return nil, fmt.Errorf("failed to setup new ca: %w", err)
	}
	revObjMap := make(map[string] *bitarray.BitArray)
	caSignedDigestMap := make(map[string]map[uint64] *mtr.SRDWithRevData)
	logSignedDigestMap := make(map[string]map[uint64]map[string] *mtr.SRDWithRevData)
	deltaRevocations := make(map[uint64] bool)
	ca := &CA{
		LogInfoMap: logInfoMap, 
		RevocationObjMap: revObjMap, 
		CASignedDigestMap: caSignedDigestMap, 
		LogSignedDigestMap: logSignedDigestMap, 
		DeltaRevocations: deltaRevocations, 
		ListenAddress: *caURL, 
		MMD: *mmd, 
		CAID:*caID,
		Signer: signer,

	}
	return ca, nil
}

// Stores the contents of ca_config.json
type CAConfig struct {
	LogIDs []string `json:"log_ids"`
	CAID string `json:"ca_id"`
	StrPrivKey string `json:"private_key"`
}

// Parse caConfig json file 
func parseCAConfig(caConfigName string) (*CAConfig, error) {
	byteData, err := utils.FiletoBytes(caConfigName)
	if err != nil {
		return nil, fmt.Errorf("error parsing ca config: %w", err)
	}
	var caConfig CAConfig
	err = json.Unmarshal(byteData, &caConfig) 
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ca config: %w", err)
	}
	return &caConfig, nil
}

// Create a map of logger LogIDs to their corresponding LogClients
func createLogInfoMap(caConfig *CAConfig, logListName string) (map[string] *entitylist.LogInfo, error) {
	logInfoMap := make(map[string] *entitylist.LogInfo)
	logList, err := entitylist.NewLogList(logListName)
	if err != nil {
		return nil, fmt.Errorf("failed to create loglist for logURLMap: %w", err)
	}

	// Iterate through all the LogIDs within caConfig and add the URLs to map along with their created logclients
	for _, logID := range caConfig.LogIDs {
		log := logList.FindLogByLogID(logID)
		if err != nil {
			return nil, fmt.Errorf("failed to create logClient for logInfoMap: %w", err)
		}
		logInfoMap[logID] = log
	}
	return logInfoMap, nil 
}

// Create signer for the CA
func createSigner(caConfig *CAConfig) (*signature.Signer, error) {
	strPrivKey := caConfig.StrPrivKey
	signer, err := signature.NewSigner(strPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer in ca: %w", err)
	}
	return signer, nil
}

// Get CAList info from caList
func getCAListInfo(caListName string, caConfig *CAConfig) (*string, *uint64, *string, error) {
	caList, err := entitylist.NewCAList(caListName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating ca list for ca config: %w", err)
	}
	caInfo := caList.FindCAByCAID(caConfig.CAID)
	csplit := strings.Split(caInfo.CAURL, ":")
	caURL := csplit[1][2:] + ":" + csplit[2]
	mmd := caInfo.MMD
	caID := caInfo.CAID
	return &caURL, &mmd, &caID, nil
}