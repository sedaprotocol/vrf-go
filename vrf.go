package vrf_secp256k1

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

// Verifies the provided VRF proof and computes the VRF hash output beta.
// Spec: `ECVRF_verify` function (section 5.2).
func (v VRFStruct) Verify(public_key, pi, alpha []byte) ([]byte, error) {
	// // Step 1-2: Y = string_to_point(PK_string)
	// let public_key_point = C::ProjectivePoint::from(self.point_from_bytes(public_key)?);
	public_key_point, err := v.UnmarshalCompressed(public_key)
	if err != nil {
		return nil, err
	}

	// TO-DO involves cofactor
	// // Step 3: If validate_key, run ECVRF_validate_key(Y) (Section 5.4.5)
	// // TODO: Check step 3 again
	// if public_key_point.is_small_order().into() {
	//     return Err(VrfError::VerifyInvalidKey);
	// }

	// Step 4-6: D = ECVRF_decode_proof(pi_string)
	gamma, c, s, err := v.DecodeProof(pi)
	if err != nil {
		return nil, err
	}
	gamma_point, err := v.UnmarshalCompressed(gamma)
	if err != nil {
		return nil, err
	}
	// let gamma_point = C::ProjectivePoint::from(self.point_from_bytes(&gamma_point_bytes)?);
	// let c_scalar = self.scalar_from_bytes(&c_scalar_bytes)?;
	// let s_scalar = self.scalar_from_bytes(&s_scalar_bytes)?;

	// Step 7: H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
	h_point, err := v.EncodeToCurveTai(public_key, alpha)
	if err != nil {
		return nil, err
	}
	h_point_bytes := v.MarshalCompressed(h_point.X, h_point.Y)

	// Step 8: U = s*B - c*Y
	// let u_point = C::ProjectivePoint::mul_by_generator(&s_scalar) - public_key_point * c_scalar;
	ax, ay := v.Curve.ScalarBaseMult(s) // public_key_point
	bx, by := v.Curve.ScalarMult(public_key_point.X, public_key_point.Y, c)
	ux, uy := v.Curve.Add(ax, ay, bx, new(big.Int).Neg(by))
	u_point_bytes := v.MarshalCompressed(ux, uy)

	// Step 9: V = s*H - c*Gamma
	// let v_point = h_point * s_scalar - gamma_point * c_scalar;
	// let v_point_bytes = v_point.to_encoded_point(true).as_bytes().to_vec();
	cx, cy := v.Curve.ScalarMult(h_point.X, h_point.Y, s)
	dx, dy := v.Curve.ScalarMult(gamma_point.X, gamma_point.Y, c)
	vx, vy := v.Curve.Add(cx, cy, dx, new(big.Int).Neg(dy))
	v_point_bytes := v.MarshalCompressed(vx, vy)

	// Step 10: c' = ECVRF_challenge_generation(Y, H, Gamma, U, V)
	var input []byte
	input = append(input, public_key...)
	input = append(input, h_point_bytes...)
	input = append(input, gamma_point.CompressedBytes(v.Curve)...)
	input = append(input, u_point_bytes...)
	input = append(input, v_point_bytes...)

	derived_c, err := v.ChallengeGeneration(input, v.CLen)
	if err != nil {
		return nil, err
	}

	paddingSize := v.PtLen - v.CLen // TO-DO PtLen vs CFieldBytesSize
	padded_derived_c := make([]byte, paddingSize)
	padded_derived_c = append(padded_derived_c, derived_c...)
	if !bytes.Equal(padded_derived_c, c) {
		return nil, fmt.Errorf("invalid VRF proof")
	}

	return v.gamma_to_hash(gamma_point)
}

// Generates the VRF proof pi from a secret key and message.
// Spec: `ECVRF_prove` function (section 5.1).
func (v VRFStruct) Prove(secret_key, alpha []byte) ([]byte, error) {
	// Step 1: derive public key from secret key as `Y = x * B`
	x1, y1 := v.Curve.ScalarBaseMult(secret_key) // public_key_point
	public_key_bytes := v.MarshalCompressed(x1, y1)

	// Step 2: Encode to curve (using TAI)
	h_point, err := v.EncodeToCurveTai(public_key_bytes, alpha)
	if err != nil {
		return nil, err
	}
	h_point_bytes := v.MarshalCompressed(h_point.X, h_point.Y)

	// Step 4: Gamma = x * H
	gpx, gpy := v.Curve.ScalarMult(h_point.X, h_point.Y, secret_key)
	gamma_point_bytes := v.MarshalCompressed(gpx, gpy)

	// Step 5: nonce (k generation)
	digest := v.Hash(h_point_bytes)
	k := v.GenerateNonce(secret_key, digest)

	// Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
	// U = k*B
	ux, uy := v.Curve.ScalarBaseMult(k) // public_key_point
	ubytes := v.MarshalCompressed(ux, uy)

	// V = k*H
	vx, vy := v.Curve.ScalarMult(h_point.X, h_point.Y, k)
	vbytes := v.MarshalCompressed(vx, vy)

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

	// k_scalar := ecdsa.HashToInt(k)
	// c_scalar := ecdsa.HashToInt(c_scalar_bytes)
	// sk_scalar := ecdsa.HashToInt(secret_key)
	k_scalar := v.HashToInt(k)
	c_scalar := v.HashToInt(c_scalar_bytes)
	sk_scalar := v.HashToInt(secret_key)

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

	// TO-DO: involves cofactor (No need bc cofactor = 1??)
	// Step 5d: H = cofactor * H (ECVRF_validate_key)
	// TODO: Check step 5d alternative `ProjectivePoint::<Self::Curve>::from(h_point).clear_cofactor().to_affine()`
	// cofactor := new(big.Int).Set(s.cofactor())
	// if cofactor.Cmp(big.NewInt(1)) != 0 {
	// 	projectivePoint := YourEllipticCurveLibrary.NewProjectivePointFromAffine(*pointOpt).Mul(cofactor)
	// 	return YourEllipticCurveLibrary.ToAffine(projectivePoint), nil
	// }

	return pointOpt, nil
}

// Function to interpret an array of bytes as a point in the curve.
// Spec: `interpret_hash_value_as_a_point(s) = sring_to_point(0x02 || s)` (section 5.5).
func (v VRFStruct) try_hash_to_point(data []byte) (*AffinePoint, error) {
	concatenatedData := append([]byte{0x02}, data...)
	return v.UnmarshalCompressed(concatenatedData)
}

func (v VRFStruct) gamma_to_hash(point *AffinePoint) ([]byte, error) {
	// Step 4: proofToHashDomainSeparatorFront = 0x03
	const proofToHashDomainSeparatorFront uint8 = 0x03

	// Step 5: proofToHashDomainSeparatorBack = 0x00
	const proofToHashDomainSeparatorBack uint8 = 0x00

	// Step 6: Compute beta
	// betaString = Hash(suiteString || proofToHashDomainSeparatorFront ||
	//                    pointToString(cofactor * Gamma) || proofToHashDomainSeparatorBack)

	// TO-DO
	// cofactor := 1 // Replace with the actual cofactor value
	// point := gamma.mul(cofactor)

	var data []byte
	data = append(data, v.SuiteID)
	data = append(data, proofToHashDomainSeparatorFront)
	data = append(data, point.CompressedBytes(v.Curve)...)
	data = append(data, proofToHashDomainSeparatorBack)
	return v.Hash(data), nil
}
