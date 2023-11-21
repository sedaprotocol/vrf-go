package vrf_secp256k1

import (
	"crypto/sha256"
	"hash"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type VRFStruct struct {
	Curve   *secp256k1.BitCurve // Elliptic Curve
	hasher  hash.Hash           // Hash function
	SuiteID uint8               // ECVRF suite string as specific by RFC9381
	CLen    int                 // Challenge length https://datatracker.ietf.org/doc/html/rfc9381#section-5.5-2.3
	PtLen   int                 // Length, in octets, of a point on E encoded as an octet string.
	// TO-DO: check if always 16??
}

// TO-DO Generalize or rename to NewK256VRF
func NewK256VRF(suiteID uint8) VRFStruct {
	return VRFStruct{
		Curve:   secp256k1.S256(),
		hasher:  sha256.New(), // TO-DO generalize?
		SuiteID: suiteID,
		CLen:    16,
		PtLen:   32,
	}
}

func (v VRFStruct) Hash(hashInput []byte) []byte {
	v.hasher.Write(hashInput)
	hashString := v.hasher.Sum(nil)
	v.hasher.Reset()
	return hashString
}
