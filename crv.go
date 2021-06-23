package ctca

import (
	"fmt"
	"bytes"
	"io/ioutil"

	"github.com/Workiva/go-datastructures/bitarray"
	"github.com/ulikunitz/xz"
)

const (
	MaxBitsInRevocationNumber = 32
)

// Compress a given crv using xz compression
func CompressCRV(crv *bitarray.BitArray) ([]byte, error) {
	serializedCRV, err := bitarray.Marshal(*crv)
	if err != nil {
        return nil, fmt.Errorf("failed to serialize crv: %v", err)
	}
	var buf bytes.Buffer
    w, err := xz.NewWriter(&buf)
    if err != nil {
        return nil, fmt.Errorf("xz.NewWriter error %v", err)
    }
    if _, err := w.Write(serializedCRV); err != nil {
        return nil, fmt.Errorf("WriteString error %v", err)
    }
    if err := w.Close(); err != nil {
        return nil, fmt.Errorf("w.Close error %v", err)
	}
	return buf.Bytes(), nil
}

// Decompress a given xz compressed crv
func DecompressCRV(compressedCRV []byte) (*bitarray.BitArray, error) {
	buf := bytes.NewBuffer(compressedCRV)
    r, err := xz.NewReader(buf)
    if err != nil {
        return nil, fmt.Errorf("NewReader error %s", err)
	}
    decompCRV, err := ioutil.ReadAll(r)
	if err != nil {
        return nil, fmt.Errorf("failed to decompress: %v", err)
	}
	crv, err := bitarray.Unmarshal(decompCRV)
	if err != nil {
        return nil, fmt.Errorf("failed to unmarshal crv: %v", err)
	}
	return &crv, nil
}

// Convert a list of revocationNumbers to a crv bitarray of delta certificates
func GetCRVDelta(revocationNumbers []uint64) (*bitarray.BitArray) {
	maxNum := max(revocationNumbers)
	crvDelta := bitarray.NewBitArray(maxNum + 1)	
	for _, revocationNum := range revocationNumbers {
		crvDelta.SetBit(revocationNum)
	}
	return &crvDelta
}

// Convert a list of revocationNumbers to a crv bitarray
func CreateCRV(revocationNumbers []uint64, length uint64) (*bitarray.BitArray) {
	maxRevNum := max(revocationNumbers)
	bitArrayLength := max([]uint64{maxRevNum, length})
	crvDelta := bitarray.NewBitArray(bitArrayLength + 1)	
	crvDelta.Reset()
	for _, revocationNum := range revocationNumbers {
		crvDelta.SetBit(revocationNum)
	}
	return &crvDelta
}

// OR the crv and delta crv to get the most recent version of the crv
func ApplyCRVDeltaToCRV(crv, crvDelta *bitarray.BitArray) *bitarray.BitArray {
	newCRV := (*crv).Or(*crvDelta)
	return &newCRV
}

// Check the equality of two crvs
func Equals(crv1, crv2 *bitarray.BitArray) bool {
	return (*crv1).Equals(*crv2)
}

// Find the max value in a list
func max(array []uint64) uint64 {
    max := uint64(0)
    for _, value := range array {
        if max < value {
            max = value
        }
    }
    return max
}
