package vrf_secp256k1

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	ethsecp "github.com/ethereum/go-ethereum/crypto/secp256k1"
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
func UnmarshalCompressed(data []byte) (*AffinePoint, error) {
	ap := new(AffinePoint)

	// TO-DO generalize since it currently assumes secp256k1
	ap.X, ap.Y = ethsecp.DecompressPubkey(data)
	if ap.X == nil {
		return nil, errors.New("failed to unmarshal bytes to an elliptic curve point")
	}
	// return elliptic.UnmarshalCompressed(v.Curve, data) // fails due to -3x in NIST curve

	return ap, nil
}

// TO-DO
// - Unmarshal function
// - Choose library
// crypto/elliptic
// 	gamma_point_bytes := elliptic.MarshalCompressed(v.Curve, gpx, gpy)
// or
// go-ethereum/crypto/secp256k1 Marshal
