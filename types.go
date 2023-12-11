package vrf_secp256k1

import (
	"crypto/sha256"
	"errors"
	"hash"
	"math/big"

	scalar "github.com/decred/dcrd/dcrec/secp256k1/v4"
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

// UnmarshalCompressed parses an array of bytes in the 33-byte compressed
// format into a point in the curve and sets p to it.
func (p *AffinePoint) UnmarshalCompressed(data []byte) error {
	p.X, p.Y = secp256k1.DecompressPubkey(data)
	if p.X == nil {
		return errors.New("failed to unmarshal bytes to an elliptic curve point")
	}
	return nil
}

// Bytes converts the (x,y) coordinate of a point in the curve
// into the compressed form specified in SEC 1, Version 2.0, Section 2.3.3.
func (p AffinePoint) Bytes() []byte {
	return secp256k1.CompressPubkey(p.X, p.Y)
}

type VRFStruct struct {
	curve   *secp256k1.BitCurve
	hasher  hash.Hash // Hash function
	SuiteID uint8     // ECVRF suite string as specific by RFC9381
	CLen    int       // Challenge length https://datatracker.ietf.org/doc/html/rfc9381#section-5.5-2.3
	PtLen   int       // Length, in octets, of a point on E encoded as an octet string.
}

// NewK256VRF creates a new VRF Struct object with secp256k1 curve
// and SHA256 hasher.
func NewK256VRF() VRFStruct {
	return VRFStruct{
		curve:   secp256k1.S256(),
		hasher:  sha256.New(),
		SuiteID: 0xFE,
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

// Taken from https://go.dev/src/crypto/ecdsa/ecdsa_legacy.go
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

// AffineAdd adds two affine points and returns the resulting
// affine point.
func (v VRFStruct) AffineAdd(a, b *AffinePoint) *AffinePoint {
	result := new(AffinePoint)
	result.X, result.Y = v.curve.Add(a.X, a.Y, b.X, b.Y)
	return result
}

// AffineAdd subtracts the second affine point from the first
// and returns the resultings affine point.
func (v VRFStruct) AffineSub(a, b *AffinePoint) *AffinePoint {
	result := new(AffinePoint)
	result.X, result.Y = v.curve.Add(a.X, a.Y, b.X, new(big.Int).Neg(b.Y))
	return result
}

// ScalarBasePointMult multiplies the base point by a scalar and
// returns the resulting affine point.
func (v VRFStruct) ScalarBasePointMult(scalar []byte) *AffinePoint {
	result := new(AffinePoint)
	result.X, result.Y = v.curve.ScalarBaseMult(scalar)
	return result
}

// ScalarAffinePointMult multiplies an affine point by a scalar and
// returns the resulting affine point.
func (v VRFStruct) ScalarAffinePointMult(point *AffinePoint, scalar []byte) *AffinePoint {
	result := new(AffinePoint)
	result.X, result.Y = v.curve.ScalarMult(point.X, point.Y, scalar)
	return result
}

// ScalarAdd adds two scalars and returns the resulting scalar.
func (v VRFStruct) ScalarAdd(a, b []byte) []byte {
	aScalar, bScalar := new(scalar.ModNScalar), new(scalar.ModNScalar)
	aScalar.SetByteSlice(a)
	bScalar.SetByteSlice(b)

	result := aScalar.Add(bScalar).Bytes()
	return result[:]
}

// ScalarMult multiplies two scalars and returns the resulting scalar.
func (v VRFStruct) ScalarMult(a, b []byte) []byte {
	aScalar, bScalar := new(scalar.ModNScalar), new(scalar.ModNScalar)
	aScalar.SetByteSlice(a)
	bScalar.SetByteSlice(b)

	result := aScalar.Mul(bScalar).Bytes()
	return result[:]
}
