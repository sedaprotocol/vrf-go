package vrf_secp256k1

import (
	"crypto/sha256"
	"hash"
	"math/big"

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

// from https://go.dev/src/crypto/ecdsa/ecdsa_legacy.go
// HashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func (v VRFStruct) HashToInt(hash []byte) *big.Int {
	orderBits := v.Curve.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
