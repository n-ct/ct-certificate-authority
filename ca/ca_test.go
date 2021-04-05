package ca

import (
	"testing"
	"reflect"
	"time"
	"fmt"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/google/certificate-transparency-go/tls"
	ctca "github.com/n-ct/ct-certificate-authority"
)

var (
	caConfigName = "../testdata/ca_config.json"
	caListName = "../testdata/ca_list.json"
	logListName = "../testdata/log_list.json"
	pubKeyStr = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmFk6QT48Ts4oxSkBPM4mQ/mnWICKVmZUP6urQVBH0vhDzJVYHc2ShvF2KjWzorVu2C+tY6lIU+61iiPLsGvZXw=="
	revType = "Let's-Revoke"
)

func mustGetCA(t *testing.T) (*CA, error) {
	t.Helper()
	return NewCA(caConfigName, caListName, logListName)
}

func TestNewCA(t *testing.T) {
	_, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestAddRevocationNumsAndDeltaRevocationsToList(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	revNumsList := []uint64{1}
	err = newCA.AddRevocationNums(&revNumsList)
	if err != nil {
		t.Fatalf("failed to add new revNums: %v", err)
	}

	deltaRevNumsList := newCA.DeltaRevocationsToList()
	if !reflect.DeepEqual(deltaRevNumsList, revNumsList) {
		t.Fatalf("DeltaRevocations (%v) not equal to previous added revNumsList (%v)", deltaRevNumsList, revNumsList)
	}
}

func mustGetSRDWithRevData(t *testing.T, newCA *CA, timestamp uint64) (*mtr.SRDWithRevData, error) {
	t.Helper()
	crv := ctca.CreateCRV([]uint64{1,2,3}, 0)
	deltaCRV := ctca.GetCRVDelta([]uint64{3})
	srd, err := CreateSRDWithRevData(crv, deltaCRV, timestamp, newCA.CAID, tls.SHA256, newCA.Signer)
	return srd, err
}

func TestAddGetCASRDRoundTrip(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	timestamp := uint64(time.Now().Unix())
	srd, err := mustGetSRDWithRevData(t, newCA, timestamp)
	if err != nil {
		t.Fatalf("failed to create SRD: %v", err)
	}
	
	if err := newCA.AddCASRD(srd); err != nil {
		t.Fatalf("failed to add SRD to CA: %v", err)
	}

	_, err = newCA.GetCASRD(revType, timestamp)
	if err != nil {
		t.Fatalf("failed to get SRD from CA: %v", err)
	}
}

func TestAddGetLogSRDRoundTrip(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	timestamp := uint64(time.Now().Unix())
	srd, err := mustGetSRDWithRevData(t, newCA, timestamp)
	if err != nil {
		t.Fatalf("failed to create SRD: %v", err)
	}
	
	if err := newCA.AddLogSRD(srd); err != nil {
		t.Fatalf("failed to add SRD to CA: %v", err)
	}

	_, err = newCA.GetLogSRD(revType, timestamp, newCA.CAID)
	if err != nil {
		t.Fatalf("failed to get SRD from CA: %v", err)
	}
}

func TestGetRecentLogSRDCTObjecList(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	timestamp := uint64(time.Now().Unix())
	srd, err := mustGetSRDWithRevData(t, newCA, timestamp)
	if err != nil {
		t.Fatalf("failed to create SRD: %v", err)
	}
	
	if err := newCA.AddLogSRD(srd); err != nil {
		t.Fatalf("failed to add SRD to CA: %v", err)
	}

	logSRDCTObjList, err := newCA.GetRecentLogSRDCTObjecList(revType, timestamp)
	if err != nil {
		t.Fatalf("failed to create SRDCTObjList: %v", err)
	}

	if len(logSRDCTObjList) != 1 {
		t.Fatalf("invalid length of SRDCTObjList (%v): %v", len(logSRDCTObjList), err)
	}
}

func TestClearDeltaRevocations(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	revNumsList := []uint64{1,2,3}
	err = newCA.AddRevocationNums(&revNumsList)
	if err != nil {
		t.Fatalf("failed to add new revNums: %v", err)
	}

	if err := newCA.ClearDeltaRevocations(); err != nil {
		t.Errorf("failed to clear DeltaRevocation: %v", err)
	}

	deltaRevNumsList := newCA.DeltaRevocationsToList()
	if len(deltaRevNumsList) != 0 {
		t.Fatalf("failed to clear DeltaRevocation. (%v) remains: %v", deltaRevNumsList, err)
	}

}

func TestDoRevocationTransparencyTasks(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	revNumsList := []uint64{1, 2, 3}
	err = newCA.AddRevocationNums(&revNumsList)
	if err != nil {
		t.Fatalf("failed to add new revNums: %v", err)
	}

	if err := newCA.DoRevocationTransparencyTasks(revType); err != nil {
		t.Fatalf("failed to DoRevocationTransparencyTasks: %v", err)
	}

	srd, err := newCA.GetCASRD(revType, newCA.PreviousMMDTimestamp)
	if err != nil {
		t.Fatalf("failed to get SRD from CA: %v", err)
	}

	deltaCRV, err := ctca.DecompressCRV(srd.RevData.CRVDelta)
	if err != nil {
		t.Fatalf("failed to decompress CRVDelta from RevData: %v", err)
	}

	deltaCRVRevNumsList := (*deltaCRV).ToNums()
	if !reflect.DeepEqual(deltaCRVRevNumsList, revNumsList) {
		t.Fatalf("DeltaRevocations (%v) not equal to previous added revNumsList (%v)", deltaCRVRevNumsList, revNumsList)
	}
}

func TestCreateSRDWithRevData(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	timestamp := uint64(time.Now().Unix())
	_, err = mustGetSRDWithRevData(t, newCA, timestamp)
	if err != nil {
		t.Fatalf("failed to create SRD: %v", err)
	}
}

func TestUpdateMMD(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	if err := newCA.UpdateMMD(); err != nil {
		t.Fatalf("failed to update mmd of CA: %v", err)
	}
	mmdDur, err := time.ParseDuration(fmt.Sprintf("%v", newCA.MMD) + "s")
	if err != nil {
		t.Fatalf("failed to parse mmd into duration: %v", err)
	}
	time.Sleep(mmdDur)
	prevTimestamp := newCA.PreviousMMDTimestamp
	if err := newCA.UpdateMMD(); err != nil {
		t.Fatalf("failed to update mmd of CA: %v", err)
	}

	expectedTimestamp := prevTimestamp + newCA.MMD
	if expectedTimestamp != newCA.PreviousMMDTimestamp {
		t.Fatalf("failed to correctly update mmd of CA. Expected MMD (%v). Actual MMD (%v): %v", expectedTimestamp, newCA.PreviousMMDTimestamp, err)
	}
}

func TestPostCASRD(t *testing.T) {

}

func TestVerifySRDSignature(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	timestamp := uint64(time.Now().Unix())
	srd, err := mustGetSRDWithRevData(t, newCA, timestamp)
	if err != nil {
		t.Fatalf("failed to create SRD: %v", err)
	}

	validSRD := srd.SRD
	if err := VerifySRDSignature(&validSRD, pubKeyStr); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}

	invalidSRD := validSRD
	invalidSRD.RevDigest.Timestamp = 1
	if err := VerifySRDSignature(&invalidSRD, pubKeyStr); err == nil {
		t.Fatalf("failed to catch invalid signature: %v", err)
	}
}

func TestGetLatestRevocationStatus(t *testing.T) {
	newCA, err := mustGetCA(t)
	if err != nil {
		t.Fatalf("failed to create new CA: %v", err)
	}
	if err := newCA.UpdateMMD(); err != nil {
		t.Fatalf("failed to update mmd of CA: %v", err)
	}
	srd, err := mustGetSRDWithRevData(t, newCA, newCA.PreviousMMDTimestamp)
	if err != nil {
		t.Fatalf("failed to create SRD: %v", err)
	}
	
	if err := newCA.AddLogSRD(srd); err != nil {
		t.Fatalf("failed to add SRD to LogSRDList in CA: %v", err)
	}
	if err := newCA.AddCASRD(srd); err != nil {
		t.Fatalf("failed to add SRD to CASRDList in CA: %v", err)
	}

	mmdDur, err := time.ParseDuration(fmt.Sprintf("%v", newCA.MMD) + "s")
	if err != nil {
		t.Fatalf("failed to parse mmd into duration: %v", err)
	}
	time.Sleep(mmdDur)
	if err := newCA.UpdateMMD(); err != nil {
		t.Fatalf("failed to update mmd of CA: %v", err)
	}

	revocationStatus, err := newCA.GetLatestRevocationStatus()
	if err != nil {
		t.Fatalf("failed to add GetLatestRevocationStatus: %v", err)
	}

	if len(revocationStatus.LogSRDs) != 1 {
		t.Fatalf("invalid RevocationStatus (%v) with length (%v) : %v", revocationStatus, len(revocationStatus.LogSRDs), err)
	}
}