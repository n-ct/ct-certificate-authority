package handler

import (
	/*"fmt"
	"encoding/json"
	*/
	"net/http"

	"github.com/golang/glog"

	"github.com/n-ct/ct-monitor/monitor"
)

type Handler struct {
	m *monitor.Monitor
}

func NewHandler(m *monitor.Monitor) Handler {
	return Handler{m}
}

func writeWrongMethodResponse(rw *http.ResponseWriter, allowed string) {
	(*rw).Header().Add("Allow", allowed)
	(*rw).WriteHeader(http.StatusMethodNotAllowed)
}

func writeErrorResponse(rw *http.ResponseWriter, status int, body string) {
	(*rw).WriteHeader(status)
	(*rw).Write([]byte(body))
}

func (h *Handler) PostLogRevocationDigest(rw http.ResponseWriter, req *http.Request){
	glog.V(1).Infoln("Received PostLogRevocationDigest Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
	/*
	decoder := json.NewDecoder(req.Body)
	var ctObject mtr.CTObject
	if err := decoder.Decode(&ctObject); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid Audit Request: %v", err))
		return
	}

	if ctObject.TypeID != mtr.STHTypeID{
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Invalid STH CTObject. Need %s", mtr.STHTypeID))
		return
	}

	// Get ctObject audit response. This can either be PoM CTObject or AuditOK CTObject
	auditResp, err := h.m.AuditSTH(&ctObject)
	if err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("failed to audit: %v", err))
		return
	}
	encoder := json.NewEncoder(rw)
	if err := encoder.Encode(*auditResp); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode Audit Response to return: %v", err))
		return
	}
	rw.WriteHeader(http.StatusOK)
	*/
}

func (h *Handler) GetRevocationStatus(rw http.ResponseWriter, req *http.Request) {
	glog.Infoln("Received GetRevocationStatus request")
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
	/*
	logID, ok := req.URL.Query()["log-id"]
	if !ok {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("STHGossip request missing log-id param"))
		return
	}
	logClient, ok := h.m.LogIDMap[logID[0]]
	if !ok {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("STHGossip request log-id param value invalid. %v log-id not found in Monitor's LogIDMap", logID))
		return
	}
	ctx := context.Background()
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Monitor failed to getSTH from logger with log-id (%v): %v", logID, err))
		return
	}
	h.m.Gossip(sth)
	rw.WriteHeader(http.StatusOK)
	*/
}