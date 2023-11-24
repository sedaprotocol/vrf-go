package vrf_secp256k1

import (
	"crypto/sha256"
	"errors"
	"hash"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Domain separation tags
const encodeToCurveDSTFront byte = 0x01
const encodeToCurveDSTBack byte = 0x00
const proofToHashDSTFront uint8 = 0x03
const proofToHashDSTBack uint8 = 0x00

type AffinePoint struct {
	X, Y *big.Int
}

type VRFStruct struct {
	curve   *secp256k1.BitCurve
	hasher  hash.Hash // Hash function
	SuiteID uint8     // ECVRF suite string as specific by RFC9381
	CLen    int       // Challenge length https://datatracker.ietf.org/doc/html/rfc9381#section-5.5-2.3
	PtLen   int       // Length, in octets, of a point on E encoded as an octet string.
	// TO-DO: check if always 16??
}

func NewK256VRF(suiteID uint8) VRFStruct {
	return VRFStruct{
		curve:   secp256k1.S256(),
		hasher:  sha256.New(),
		SuiteID: suiteID,
		CLen:    16,
		PtLen:   32,
	}
}

func (v VRFStruct) N() *big.Int {
	return v.curve.Params().N
}
func (v VRFStruct) Hash(hashInput []byte) []byte {
	v.hasher.Write(hashInput)
	hashString := v.hasher.Sum(nil)
	v.hasher.Reset()
	return hashString
}

// TO-DO Compare with ecdsa.HashToInt(k)
// from https://go.dev/src/crypto/ecdsa/ecdsa_legacy.go
// HashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func (v VRFStruct) HashToInt(hash []byte) *big.Int {
	orderBits := v.curve.Params().N.BitLen()
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

// AffineAdd returns a+b.
func (v VRFStruct) AffineAdd(a, b *AffinePoint) *AffinePoint {
	result := new(AffinePoint)
	result.X, result.Y = v.curve.Add(a.X, a.Y, b.X, b.Y)
	return result
}

// AffineAdd returns a-b.
func (v VRFStruct) AffineSub(a, b *AffinePoint) *AffinePoint {
	result := new(AffinePoint)
	result.X, result.Y = v.curve.Add(a.X, a.Y, b.X, new(big.Int).Neg(b.Y))
	return result
}

func (v VRFStruct) ScalarBaseMult(scalar []byte) *AffinePoint {
	result := new(AffinePoint)
	result.X, result.Y = v.curve.ScalarBaseMult(scalar)
	return result
}

func (v VRFStruct) ScalarMult(point *AffinePoint, scalar []byte) *AffinePoint {
	result := new(AffinePoint)
	result.X, result.Y = v.curve.ScalarMult(point.X, point.Y, scalar)
	return result
}

func (v VRFStruct) ScalarMul(a, b []byte) []byte {
	aInt := v.HashToInt(a)
	bInt := v.HashToInt(b)

	result := new(big.Int)
	result.Mul(aInt, bInt)
	return result.Mod(result, v.N()).Bytes() // TO-DO Why modulo N not P?
}

func (v VRFStruct) ScalarAdd(a, b []byte) []byte {
	aInt := v.HashToInt(a)
	bInt := v.HashToInt(b)

	result := new(big.Int)
	result.Add(aInt, bInt)
	return result.Mod(result, v.N()).Bytes() // TO-DO Why modulo N not P?
}

// UnmarshalCompressed parses an array of bytes in the 33-byte compressed
// format into a point in the curve.
func (v VRFStruct) UnmarshalCompressed(data []byte) (*AffinePoint, error) {
	ap := new(AffinePoint)
	ap.X, ap.Y = secp256k1.DecompressPubkey(data)
	if ap.X == nil {
		return nil, errors.New("failed to unmarshal bytes to an elliptic curve point")
	}
	return ap, nil
}

// MarshalCompressed converts the (x,y) coordinate of a point in the curve
// into the compressed form specified in SEC 1, Version 2.0, Section 2.3.3.
func (v VRFStruct) MarshalCompressed(point *AffinePoint) []byte {
	return secp256k1.CompressPubkey(point.X, point.Y)
}
