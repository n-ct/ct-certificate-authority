package handler

import (
	"fmt"
	"encoding/json"
	"net/http"

	"github.com/golang/glog"
	"github.com/n-ct/ct-certificate-authority/ca"

	mtr "github.com/n-ct/ct-monitor"
)

type Handler struct {
	c *ca.CA
}

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

func (h *Handler) PostLogSRDWithRevData(rw http.ResponseWriter, req *http.Request){
	glog.Infoln("Received PostLogRevocationDigest Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "GET")
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
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("invalid srd signature: %v", err))
		return
	}

	// Add the Log SRD to map
	if err := h.c.AddLogSRD(&srd); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("failed to add to ca data structure: %v", err))
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
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode RevocationStatus response to return: %v", err))
		return
	}
	rw.WriteHeader(http.StatusOK)
}

type PostNewRevocationNumsRequest struct {
	RevocationNums []uint64
}

func (h *Handler) PostNewRevocationNums(rw http.ResponseWriter, req *http.Request){
	glog.Infoln("Received PostNewRevocationNums Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
	decoder := json.NewDecoder(req.Body)
	var newRevList PostNewRevocationNumsRequest
	if err := decoder.Decode(&newRevList); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid PostNewRevocationNums Request: %v", err))
		return
	}
	glog.Infoln(newRevList)
	h.c.AddRevocationNums(&newRevList.RevocationNums)

	rw.WriteHeader(http.StatusOK)
}