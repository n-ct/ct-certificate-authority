package handler

import (
	"fmt"
	"encoding/json"
	"net/http"
	"bytes"

	"github.com/golang/glog"
	"github.com/n-ct/ct-certificate-authority/ca"

	mtr "github.com/n-ct/ct-monitor"
	ctca "github.com/n-ct/ct-certificate-authority"
)

type Handler struct {
	c *ca.CA
}

// Create a new Handler instance
func NewHandler(c *ca.CA) Handler {
	return Handler{c}
}

func writeWrongMethodResponse(rw *http.ResponseWriter, allowed string) {
	(*rw).Header().Add("Allow", allowed)
	(*rw).WriteHeader(http.StatusMethodNotAllowed)
}

func writeErrorResponse(rw *http.ResponseWriter, status int, body string) {
	(*rw).WriteHeader(status)
	(*rw).Write([]byte(body))
}

// Handle a post request for an SRDWithRevData from a Logger
func (h *Handler) PostLogSRDWithRevData(rw http.ResponseWriter, req *http.Request){
	glog.Infoln("Received PostLogRevocationDigest Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}
	decoder := json.NewDecoder(req.Body)
	var srd mtr.SRDWithRevData
	if err := decoder.Decode(&srd); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid PostLogSRDWithRevData Request: %v", err))
		return
	}

	// Verify Signature
	if err := h.c.VerifyLogSRDSignature(&srd.SRD); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("invalid logSRD signature: %v", err))
		return
	}

	// Add the Log SRD to map
	if err := h.c.AddLogSRD(&srd); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("failed to add logSRD ca data structure: %v", err))
		return
	}
	/*encoder := json.NewEncoder(rw)
	if err := encoder.Encode(*auditResp); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode Audit Response to return: %v", err))
		return
	}
	*/
	rw.WriteHeader(http.StatusOK)
}

// Handle a request to get the revocation status of the most recent MMD
func (h *Handler) GetRevocationStatus(rw http.ResponseWriter, req *http.Request) {
	glog.Infoln("Received GetRevocationStatus request")
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
	revocationStatus, err := h.c.GetLatestRevocationStatus()
	if err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't produce revocationStatus: %v", err))
	}
	encoder := json.NewEncoder(rw)
	if err := encoder.Encode(*revocationStatus); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode RevocationStatus response: %v", err))
		return
	}
	rw.WriteHeader(http.StatusOK)
}

// Handle request to add new revoked certificate numbers
func (h *Handler) PostNewRevocationNums(rw http.ResponseWriter, req *http.Request){
	glog.Infoln("Received PostNewRevocationNums Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}
	decoder := json.NewDecoder(req.Body)
	var newRevList ctca.PostNewRevocationNumsRequest
	if err := decoder.Decode(&newRevList); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid PostNewRevocationNums Request: %v", err))
		return
	}
	h.c.AddRevocationNums(&newRevList.RevocationNums)
	rw.WriteHeader(http.StatusOK)
}

// Handle request to revoke a certain number of certificates and to produce an SRD with the newly revoked certificates
func (h *Handler) RevokeAndProduceSRD(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
	glog.Infoln("Received RevokeAndProduceSRD request")
	decoder := json.NewDecoder(req.Body)
	var revAndProdSRDReq ctca.RevokeAndProduceSRDRequest
	if err := decoder.Decode(&revAndProdSRDReq); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid RevokeAndProduceSRDRequest: %v", err))
		return
	}

	// TEMP FIX to access same data from same timestamp
	srd, err := h.c.GetCASRD("Let's-Revoke", h.c.PreviousMMDTimestamp)
	if err != nil {
		srd, err = h.c.RevokeAndProduceSRD(revAndProdSRDReq.TotalCerts, revAndProdSRDReq.PercentRevoked)
		if err != nil {
			writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("failed to produce SRDWithRevData for request: %v", err))
			return
		}
	}

	encoder := json.NewEncoder(rw)
	if err := encoder.Encode(*srd); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode SRDWithRevData (%v) in response: %v", srd, err))
		return
	}

	constSRD := srd.SRD
	ct, err := mtr.ConstructCTObject(&constSRD)
	glog.Infof("%v", ct)
	if err != nil {
		glog.Infof("%v", err)
	}
	size, _ := GetSize(ct)
	glog.Infof("Size of srd: %v", size)


	rw.WriteHeader(http.StatusOK)
}

// Convert given object to json and then get the size
func GetSize(i interface{}) (int, error) {
	b := new(bytes.Buffer)
    if err := json.NewEncoder(b).Encode(i); err != nil {
		return 0, fmt.Errorf("Failed to encode object of type (%T): %v", i, err)
	}
	return b.Len(), nil
}
