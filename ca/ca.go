package ca

import (
	/*"fmt"
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/golang/glog"
	*/
	"github.com/Workiva/go-datastructures/bitarray"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/signature"
)

type CA struct {
	LogURLMap map[string] string // Maybe just have this be map[log]logURL
	RevocationObjMap map[string] *bitarray.BitArray
	CASignedDigestMap map[string][uint64] *mtr.SRDWithRevData
	LogSignedDigestMap map[string][uint64] *mtr.SRDWithRevData
	ListenAddress string 
	MMD	uint64
	Signer *signature.Signer
}

// Create a new CA using the createCA function found in ca_setup.go
func NewCA(caConfigName string, caListName string, logListName string) (*CA, error){
	return createCA(caConfigName, caListName, logListName)
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