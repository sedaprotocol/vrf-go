package vrf_secp256k1

import (
	"crypto/sha256"
	"hash"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type VRFStruct struct {
	// Elliptic Curve
	Curve *secp256k1.BitCurve
	// Hash Function
	hasher hash.Hash
	/// ECVRF suite string as specific by RFC9381
	SuiteID uint8
	CLen    int // challenge length https://datatracker.ietf.org/doc/html/rfc9381#section-5.5-2.3
	// TO-DO: check if always 16??
}

func NewVRF(suiteID uint8) VRFStruct {
	return VRFStruct{
		Curve:   secp256k1.S256(),
		hasher:  sha256.New(), // TO-DO
		SuiteID: suiteID,
		CLen:    16,
	}
}

func (v VRFStruct) Hash(hashInput []byte) []byte {
	v.hasher.Write(hashInput)
	hashString := v.hasher.Sum(nil)
	v.hasher.Reset()
	return hashString
}
