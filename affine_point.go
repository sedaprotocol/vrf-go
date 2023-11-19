package vrf_secp256k1

import (
	"crypto/elliptic"
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

// TO-DO generalize since it currently assumes secp256k1
func UnmarshalCompressed(data []byte) (*big.Int, *big.Int) {
	// return elliptic.UnmarshalCompressed(v.Curve, data) // fails due to -3x in NIST curve
	return ethsecp.DecompressPubkey(data)
}
