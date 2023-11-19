package vrf_secp256k1

import (
	"crypto/elliptic"
	"math/big"
)

type AffinePoint struct {
	X, Y *big.Int
}

func (ap AffinePoint) CompressedBytes(curve elliptic.Curve) []byte {
	bytes := elliptic.MarshalCompressed(curve, ap.X, ap.Y)
	return bytes
}
