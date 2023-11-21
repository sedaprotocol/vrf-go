package vrf_secp256k1_test

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/assert"

	vrf "github.com/sedaprotocol/vrf-go"
)

// from vrf-rs/src/tests/secp256k1_sha256_tai.rs encode_to_curve_tai()
func TestSecp256k1Sha256TaiEncodeToCurve2(t *testing.T) {
	vrf := vrf.NewK256VRF(0xFE)
	publicKey, err := hex.DecodeString("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("sample")
	point, err := vrf.EncodeToCurveTai(publicKey, alpha)
	if err != nil {
		t.Fatal(err)
	}
	compressedPoint := point.CompressedBytes(secp256k1.S256())

	expectedPoint, err := hex.DecodeString("0221ceb1ce22cd34d8b73a619164ed64e917ca31fd454075d02e4bdfa9c5ce0b48")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedPoint, compressedPoint)
}

// from vrf-rs/src/tests/secp256k1_sha256_tai.rs prove()
func TestProve(t *testing.T) {
	vrf := vrf.NewK256VRF(0xFE)
	secretKey, err := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("sample")

	pi, err := vrf.Prove(secretKey, alpha)
	if err != nil {
		t.Fatal(err)
	}

	expectedPi, err := hex.DecodeString("03cc8a4f11c8dde5cbaad50f523c43389aa9eb407288570cf2bcd2e524ac0cbf88123d52707735b2ecff030dbdd71ac3a20166e4fb77f254dae61c6a35c694e539ae2d51e2ffce166cc455386aadb28bad")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedPi, pi)
}

// from vrf-rs/src/tests/secp256k1_sha256_tai.rs verify()
func TestVerify(t *testing.T) {
	vrf := vrf.NewK256VRF(0xFE)
	publicKey, err := hex.DecodeString("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("sample")
	pi, err := hex.DecodeString("0338ec99b5d0f94ebcc2c704c04af3de8b4289df8798e5fb9f920d7f5d77ac03d7718b9677d1c9348649ac2ec4f7ecbe519b30dd10c4eb5efc21dd5944709f2f3b7e97a25f6f095334593502d05103bc5b")
	if err != nil {
		t.Fatal(err)
	}

	beta, err := vrf.Verify(publicKey, pi, alpha)
	if err != nil {
		t.Fatal(err)
	}

	expectedBeta, err := hex.DecodeString("d466c22e14dc3b7fd169668dd3ee9ac6351429a24aebc5e8af61a0f0de89b65a")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedBeta, beta)
}
