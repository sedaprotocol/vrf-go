package vrf_secp256k1_test

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	vrf "github.com/sedaprotocol/vrf-go"
)

// Struct to represent the JSON structure
type Entry struct {
	Hash    string `json:"hash"`
	Message string `json:"message"`
	Pi      string `json:"pi"`
	Priv    string `json:"priv"`
	Pub     string `json:"pub"`
}

func decodeEntry(t *testing.T, entry Entry) (beta, alpha, pi, privKey, pubKey []byte) {
	var err error
	beta, err = hex.DecodeString(entry.Hash)
	if err != nil {
		t.Fatal(err)
	}
	alpha, err = hex.DecodeString(entry.Message)
	if err != nil {
		t.Fatal(err)
	}
	pi, err = hex.DecodeString(entry.Pi)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err = hex.DecodeString(entry.Priv)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err = hex.DecodeString(entry.Pub)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestProveVerify(t *testing.T) {
	testFile := "./ECVRF_SECP256K1_SHA256_TAI.json"
	jsonData, err := os.ReadFile(testFile)
	if err != nil {
		log.Fatal(err)
	}

	var entries []Entry
	err = json.Unmarshal(jsonData, &entries)
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range entries {
		t.Logf("testing hash %s", entry.Hash)

		t.Run(entry.Hash, func(t *testing.T) {
			expectedBeta, alpha, expectedPi, privKey, pubKey := decodeEntry(t, entry)

			vrf := vrf.NewK256VRF(0xFE)

			pi, err := vrf.Prove(privKey, alpha)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, expectedPi, pi)

			beta, err := vrf.Verify(pubKey, pi, alpha)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, expectedBeta, beta)
		})
	}
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

// from vrf-rs/src/tests/secp256k1_sha256_tai.rs decode_proof()
func TestDecodeProof(t *testing.T) {
	vrf := vrf.NewK256VRF(0xFE)
	pi, err := hex.DecodeString("035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f")
	if err != nil {
		t.Fatal(err)
	}

	gamma, c, s, err := vrf.DecodeProof(pi)
	if err != nil {
		t.Fatal(err)
	}

	expectedGamma, err := hex.DecodeString("035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4")
	if err != nil {
		t.Fatal(err)
	}
	expectedC, err := hex.DecodeString("00000000000000000000000000000000a53f0a46f018bc2c56e58d383f2305e0")
	if err != nil {
		t.Fatal(err)
	}
	expectedS, err := hex.DecodeString("975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expectedGamma, gamma)
	assert.Equal(t, expectedC, c)
	assert.Equal(t, expectedS, s)
}

// from vrf-rs/src/tests/secp256k1_sha256_tai.rs encode_to_curve_tai()
func TestSecp256k1Sha256TaiEncodeToCurve2(t *testing.T) {
	vrf := vrf.NewK256VRF(0xFE)
	publicKey, err := hex.DecodeString("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
	if err != nil {
		t.Fatal(err)
	}
	alpha := []byte("sample")
	point, err := vrf.EncodeToCurveTAI(publicKey, alpha)
	if err != nil {
		t.Fatal(err)
	}
	compressedPoint := vrf.MarshalCompressed(point)

	expectedPoint, err := hex.DecodeString("0221ceb1ce22cd34d8b73a619164ed64e917ca31fd454075d02e4bdfa9c5ce0b48")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedPoint, compressedPoint)
}
