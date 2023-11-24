package vrf_secp256k1

import (
	"bytes"
	"fmt"
)

// Verifies the provided VRF proof and computes the VRF hash output beta.
// Spec: `ECVRF_verify` function (section 5.3).
func (v VRFStruct) Verify(publicKey, pi, alpha []byte) ([]byte, error) {
	// Step 1-2: Y = string_to_point(PK_string)
	publicKeyPoint, err := v.UnmarshalCompressed(publicKey)
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
	gamma, cScalar, sScalar, err := v.DecodeProof(pi)
	if err != nil {
		return nil, err
	}
	gammaPoint, err := v.UnmarshalCompressed(gamma)
	if err != nil {
		return nil, err
	}

	// Step 7: H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
	hPoint, err := v.EncodeToCurveTAI(publicKey, alpha)
	if err != nil {
		return nil, err
	}
	hBytes := v.MarshalCompressed(hPoint)

	// Step 8: U = s*B - c*Y
	sB := v.ScalarBaseMult(sScalar)
	cY := v.ScalarMult(publicKeyPoint, cScalar)
	uPoint := v.AffineSub(sB, cY)
	uBytes := v.MarshalCompressed(uPoint)

	// Step 9: V = s*H - c*Gamma
	sH := v.ScalarMult(hPoint, sScalar)
	cGamma := v.ScalarMult(gammaPoint, cScalar)
	vPoint := v.AffineSub(sH, cGamma)
	vBytes := v.MarshalCompressed(vPoint)

	// Step 10: c' = ECVRF_challenge_generation(Y, H, Gamma, U, V)
	var input []byte
	input = append(input, publicKey...)
	input = append(input, hBytes...)
	input = append(input, v.MarshalCompressed(gammaPoint)...)
	input = append(input, uBytes...)
	input = append(input, vBytes...)

	derivedC, err := v.ChallengeGeneration(input, v.CLen)
	if err != nil {
		return nil, err
	}

	paddingSize := v.PtLen - v.CLen // TO-DO PtLen vs CFieldBytesSize
	paddedDerivedC := make([]byte, paddingSize)
	paddedDerivedC = append(paddedDerivedC, derivedC...)
	if !bytes.Equal(paddedDerivedC, cScalar) {
		return nil, fmt.Errorf("invalid VRF proof")
	}

	return v.gammaToHash(gammaPoint)
}

// Generates the VRF proof pi from a secret key and message.
// Spec: `ECVRF_prove` function (section 5.1).
func (v VRFStruct) Prove(secretKey, alpha []byte) ([]byte, error) {
	// Step 1: derive public key from secret key as `Y = x * B`
	publicKeyPoint := v.ScalarBaseMult(secretKey)
	publicKeyBytes := v.MarshalCompressed(publicKeyPoint)

	// Step 2: Encode to curve (using TAI)
	hPoint, err := v.EncodeToCurveTAI(publicKeyBytes, alpha)
	if err != nil {
		return nil, err
	}
	hBytes := v.MarshalCompressed(hPoint)

	// Step 4: Gamma = x * H
	gammaPoint := v.ScalarMult(hPoint, secretKey)
	gammaBytes := v.MarshalCompressed(gammaPoint)

	// Step 5: nonce (k generation)
	digest := v.Hash(hBytes)
	kScalar := v.GenerateNonce(secretKey, digest)

	// Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
	// U = k*B
	uPoint := v.ScalarBaseMult(kScalar)
	uBytes := v.MarshalCompressed(uPoint)

	// V = k*H
	vPoint := v.ScalarMult(hPoint, kScalar)
	vBytes := v.MarshalCompressed(vPoint)

	// Challenge generation (returns hash output truncated by `cLen`)
	var input []byte
	input = append(input, publicKeyBytes...)
	input = append(input, hBytes...)
	input = append(input, gammaBytes...)
	input = append(input, uBytes...)
	input = append(input, vBytes...)

	cScalar, err := v.ChallengeGeneration(input, v.CLen)
	if err != nil {
		return nil, err
	}

	// Step 7: s = (k + c*x) mod q
	mul := v.ScalarMul(cScalar, secretKey)
	sScalar := v.ScalarAdd(mul, kScalar)

	// Step 8: encode (gamma, c, s)
	var proof []byte
	proof = append(proof, gammaBytes...)
	proof = append(proof, cScalar...)
	proof = append(proof, sScalar[:]...)

	return proof, nil
}
