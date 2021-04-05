package ctca

import (
	"testing"
	"reflect"

	//"github.com/Workiva/go-datastructures/bitarray"
	//"github.com/ulikunitz/xz"
)

func TestCompressCRVDecompressCRVRoundTrip(t *testing.T) {
	revNumsList := []uint64{1, 2, 3}
	crv := CreateCRV(revNumsList, 0)
	compCRV, err := CompressCRV(crv)
	if err != nil {
		t.Errorf("failed to compress CRV (%v): %v", crv, err)
	}
	decompCRV, err := DecompressCRV(compCRV)
	if err != nil {
		t.Errorf("failed to decompress compressed CRV (%v): %v", compCRV, err)
	}

	decompRevNumsList := (*decompCRV).ToNums()
	if !reflect.DeepEqual(decompRevNumsList, revNumsList) {
		t.Errorf("decompressed CRV (%v) not equal to previous CRV (%v): %v", decompRevNumsList, revNumsList, err)
	}
}

func TestGetCRVDelta(t *testing.T) {
	revNumsList := []uint64{1, 2, 3}
	deltaCRV := GetCRVDelta(revNumsList)
	deltaCRVRevNumsList := (*deltaCRV).ToNums()
	if !reflect.DeepEqual(deltaCRVRevNumsList, revNumsList) {
		t.Errorf("delta CRV nums (%v) not equal to previous revNums (%v)", deltaCRVRevNumsList, revNumsList)
	}
}

func TestCreateCRV(t *testing.T) {
	revNumsList := []uint64{1, 2, 3}
	crv := CreateCRV(revNumsList, 0)
	crvRevNumsList := (*crv).ToNums()
	if !reflect.DeepEqual(crvRevNumsList, revNumsList) {
		t.Errorf("CRV nums (%v) not equal to previous revNums (%v)", crvRevNumsList, revNumsList)
	}
}

func TestApplyCRVDeltaToCRV(t *testing.T) {
	crvRevNumsList := []uint64{1, 2, 3}
	crv := CreateCRV(crvRevNumsList, 0)

	deltaCRVRevNumsList := []uint64{4,5}
	deltaCRV := GetCRVDelta(deltaCRVRevNumsList)
	crvAndCRVDeltaRevNumsList := append(crvRevNumsList, deltaCRVRevNumsList...)

	newCRV := ApplyCRVDeltaToCRV(crv, deltaCRV)
	newCRVRevNumsList := (*newCRV).ToNums()
	if !reflect.DeepEqual(newCRVRevNumsList, crvAndCRVDeltaRevNumsList) {
		t.Errorf("combined new CRV nums (%v) not equal to previous revNums (%v)", newCRVRevNumsList, crvAndCRVDeltaRevNumsList)
	}
}


func TestEquals(t *testing.T) {
	firstSameRevNumsList := []uint64{1, 2, 3}
	firstSameCRV := CreateCRV(firstSameRevNumsList, 0)

	secondSameRevNumsList := []uint64{1, 2, 3}
	secondSameCRV := CreateCRV(secondSameRevNumsList, 0)

	firstDiffRevNumsList := []uint64{5}
	firstDiffCRV := CreateCRV(firstDiffRevNumsList, 0)

	if !Equals(firstSameCRV, secondSameCRV) {
		t.Errorf("firstSameCRV (%v) not equal to secondSameCRV (%v) when it should", *firstSameCRV, *secondSameCRV)
	}

	if Equals(firstSameCRV, firstDiffCRV) {
		t.Errorf("firstSameCRV (%v) equal to firstDiffCRV (%v) when it should not be", *firstSameCRV, *firstDiffCRV)
	}
}
