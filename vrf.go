package vrf_secp256k1

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
)

// / Generates a VRF proof from a secret key and message.
// / Spec: `ECVRF_prove` function (section 5.1).
func (v VRFStruct) Prove(secret_key []byte, alpha []byte) (pi []byte, err error) {
	// Step 1: derive public key from secret key as `Y = x * B`
	x1, y1 := v.Curve.ScalarBaseMult(secret_key) // public_key_point
	public_key_bytes := elliptic.MarshalCompressed(v.Curve, x1, y1)

	// new(gnark.G1Affine).ScalarMultiplicationBase(ecdsa.HashToInt(secret_key))

	// Step 2: Encode to curve (using TAI)
	h_point, err := v.EncodeToCurveTai(public_key_bytes, alpha)
	if err != nil {
		return nil, err
	}
	h_point_bytes := elliptic.MarshalCompressed(v.Curve, h_point.X, h_point.Y)

	// Step 4: Gamma = x * H
	gpx, gpy := v.Curve.ScalarMult(h_point.X, h_point.Y, secret_key)
	gamma_point_bytes := elliptic.MarshalCompressed(v.Curve, gpx, gpy)

	// Step 5: nonce (k generation)
	digest := v.Hash(h_point_bytes)
	k := v.GenerateNonce(secret_key, digest)

	// Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
	// U = k*B
	ux, uy := v.Curve.ScalarBaseMult(k) // public_key_point
	ubytes := elliptic.MarshalCompressed(v.Curve, ux, uy)

	// V = k*H
	vx, vy := v.Curve.ScalarMult(h_point.X, h_point.Y, k)
	vbytes := elliptic.MarshalCompressed(v.Curve, vx, vy)

	// Challenge generation (returns hash output truncated by `cLen`)
	var input []byte
	input = append(input, public_key_bytes...)
	input = append(input, h_point_bytes...)
	input = append(input, gamma_point_bytes...)
	input = append(input, ubytes...)
	input = append(input, vbytes...)

	c_scalar_bytes, err := v.ChallengeGeneration(input, v.CLen)
	if err != nil {
		return nil, err
	}

	k_scalar := ecdsa.HashToInt(k)
	c_scalar := ecdsa.HashToInt(c_scalar_bytes)
	sk_scalar := ecdsa.HashToInt(secret_key)

	// Step 7: s = (k + c*x) mod q
	s_scalar := new(big.Int)
	s_scalar.Mul(c_scalar, sk_scalar)
	s_scalar.Mod(s_scalar, v.Curve.N) // TO-DO Why modulo N not P?
	s_scalar.Add(s_scalar, k_scalar)
	s_scalar.Mod(s_scalar, v.Curve.N) // TO-DO Why modulo N not P?
	s_scalar_bytes := s_scalar.Bytes()

	// Step 8: encode (gamma, c, s)
	var proof []byte
	proof = append(proof, gamma_point_bytes...)
	proof = append(proof, c_scalar_bytes...)
	proof = append(proof, s_scalar_bytes[:]...)

	return proof, nil
}

func (v VRFStruct) EncodeToCurveTai(encodeToCurveSalt, alpha []byte) (*AffinePoint, error) {
	// Step 2-3: domain separators & cipher suite
	const encodeToCurveDomainSeparatorFront byte = 0x01
	const encodeToCurveDomainSeparatorBack byte = 0x00

	// Step 4-5: Loop over ctr checking if hashString is a valid EC point
	// hashString = Hash(suiteString ||
	// encodeToCurveDomainSeparatorFront ||
	// encodeToCurveSalt || alphaString || ctrString ||
	// encodeToCurveDomainSeparatorBack)
	var hashInput []byte
	hashInput = append(hashInput, v.SuiteID)
	hashInput = append(hashInput, encodeToCurveDomainSeparatorFront)
	hashInput = append(hashInput, encodeToCurveSalt...)
	hashInput = append(hashInput, alpha...)
	hashInput = append(hashInput, 0x00) // First iteration: CTR=0
	hashInput = append(hashInput, encodeToCurveDomainSeparatorBack)

	var pointOpt *AffinePoint
	ctrPosition := len(hashInput) - 2
	for i := 0; i <= 255; i++ {
		hashInput[ctrPosition] = byte(i)
		hashString := v.Hash(hashInput)
		point, err := v.try_hash_to_point(hashString)
		if err == nil {
			pointOpt = point
			break
		}
	}

	// No solution found (really unlikely with probability about 2^-256)
	if pointOpt == nil {
		return nil, errors.New("EncodeToCurveTai: no solution found")
	}

	// TO-DO: No need bc cofactor = 1??
	// Step 5d: H = cofactor * H (ECVRF_validate_key)
	// TODO: Check step 5d alternative `ProjectivePoint::<Self::Curve>::from(h_point).clear_cofactor().to_affine()`
	// cofactor := new(big.Int).Set(s.cofactor())
	// if cofactor.Cmp(big.NewInt(1)) != 0 {
	// 	projectivePoint := YourEllipticCurveLibrary.NewProjectivePointFromAffine(*pointOpt).Mul(cofactor)
	// 	return YourEllipticCurveLibrary.ToAffine(projectivePoint), nil
	// }

	return pointOpt, nil
}

func (v VRFStruct) try_hash_to_point(data []byte) (*AffinePoint, error) {
	concatenatedData := append([]byte{0x02}, data...)
	return v.point_from_bytes(concatenatedData)
}

func (v VRFStruct) point_from_bytes(data []byte) (*AffinePoint, error) {
	ap := new(AffinePoint)
	ap.X, ap.Y = UnmarshalCompressed(data)
	return ap, nil
}
