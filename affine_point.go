package vrf_secp256k1

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type AffinePoint struct {
	X, Y *big.Int
}

func (ap AffinePoint) CompressedBytes(curve elliptic.Curve) []byte {
	bytes := elliptic.MarshalCompressed(curve, ap.X, ap.Y)
	return bytes
}

// UnmarshalCompressed parses an array of bytes in the 33-byte compressed
// format into a point in the curve.
func (v VRFStruct) UnmarshalCompressed(data []byte) (*AffinePoint, error) {
	ap := new(AffinePoint)

	// TO-DO generalize since it currently assumes secp256k1
	// TO-DO below generalization fails due to -3x in NIST curve
	// ap.X, ap.Y = elliptic.UnmarshalCompressed(v.Curve, data)
	// if ap.X == nil {
	// 	return nil, errors.New("failed to unmarshal bytes to an elliptic curve point")
	// }

	ap.X, ap.Y = secp256k1.DecompressPubkey(data)
	if ap.X == nil {
		return nil, errors.New("failed to unmarshal bytes to an elliptic curve point")
	}

	return ap, nil
}

func (v VRFStruct) MarshalCompressed(x, y *big.Int) []byte {
	bytes := elliptic.MarshalCompressed(v.Curve, x, y)
	return bytes
}
