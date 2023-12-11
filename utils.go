package vrf_secp256k1

import (
	"errors"
)

// Decodes a VRF proof by extracting the gamma EC point, and parameters `c` and `s` as bytes.
// Spec: `ECVRF_decode_proof` function in section 5.4.4.
func (v VRFStruct) DecodeProof(pi []byte) (gamma []byte, cScalar []byte, sScalar []byte, err error) {
	// Expected size of proof: len(pi) = len(gamma) + len(c) + len(s)
	// len(s) = 2 * len(c), so len(pi) = len(gamma) + 3 * len(c)
	gammaOct := v.PtLen + 1
	if len(pi) != gammaOct+v.CLen*3 {
		err = errors.New("invalid pi length")
		return
	}

	// Gamma point
	gamma = make([]byte, gammaOct)
	copy(gamma, pi[0:gammaOct])

	// TO-DO: Step 5: If Gamma = "INVALID", output "INVALID" and stop

	// C scalar (needs to be padded with leading zeroes)
	cScalar = make([]byte, v.PtLen-v.CLen) // TO-DO PtLen vs CFieldBytesSize
	cScalar = append(cScalar, pi[gammaOct:gammaOct+v.CLen]...)

	// S scalar
	sScalar = make([]byte, len(pi)-gammaOct-v.CLen)
	copy(sScalar, pi[gammaOct+v.CLen:])

	return gamma, cScalar, sScalar, nil
}

func (v VRFStruct) ChallengeGeneration(points []byte, truncateLen int) ([]byte, error) {
	// Step 1: challenge_generation_domain_separator_front = 0x02
	const challengeGenerationDomainSeparatorFront byte = 0x02

	// Step 2: Initialize str = suiteString || challengeGenerationDomainSeparatorFront
	var pointBytes []byte
	pointBytes = append(pointBytes, v.SuiteID, challengeGenerationDomainSeparatorFront)

	// Step 3: For PJ in [P1, P2, P3, P4, P5]: str = str || pointToString(PJ)
	pointBytes = append(pointBytes, points...)

	// Step 4: challenge_generation_domain_separator_back = 0x00
	const challengeGenerationDomainSeparatorBack byte = 0x00

	// Step 5: str = str || challenge_generation_domain_separator_back
	pointBytes = append(pointBytes, challengeGenerationDomainSeparatorBack)

	// Step 6: c_string = Hash(str)
	c_string := v.Hash(pointBytes)

	// Step 7: truncated_c_string = c_string[0]...c_string[CLen-1]
	if truncateLen > len(c_string) {
		return nil, errors.New("truncate length exceeds hash length")
	}
	truncated_c_string := c_string[:truncateLen]

	// Step 8: c = string_to_int(truncated_c_string)
	// Note: not needed because `prove` and `verify` functions need bytes and scalar values
	return truncated_c_string, nil
}

func (v VRFStruct) EncodeToCurveTAI(encodeToCurveSalt, alpha []byte) (*AffinePoint, error) {
	// Steps 4-5: Loop over ctr checking if hashString is a valid EC point
	// 	hashString = Hash(suiteString || encodeToCurveDomainSeparatorFront ||
	//	encodeToCurveSalt || alphaString || ctrString || encodeToCurveDomainSeparatorBack)
	var hashInput []byte
	hashInput = append(hashInput, v.SuiteID)
	hashInput = append(hashInput, encodeToCurveDSTFront)
	hashInput = append(hashInput, encodeToCurveSalt...)
	hashInput = append(hashInput, alpha...)
	hashInput = append(hashInput, 0x00) // First iteration: CTR=0
	hashInput = append(hashInput, encodeToCurveDSTBack)

	var pointOpt *AffinePoint
	ctrPosition := len(hashInput) - 2
	for i := 0; i <= 255; i++ {
		hashInput[ctrPosition] = byte(i)
		hashString := v.Hash(hashInput)
		point, err := v.tryHashToPoint(hashString)
		if err == nil {
			pointOpt = point
			break
		}
	}

	// No solution found (really unlikely with probability about 2^-256)
	if pointOpt == nil {
		return nil, errors.New("EncodeToCurveTai: no solution found")
	}

	// TO-DO: cofactor (No need bc cofactor = 1??)
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
func (v VRFStruct) tryHashToPoint(data []byte) (*AffinePoint, error) {
	concatenatedData := append([]byte{0x02}, data...)
	point := new(AffinePoint)
	err := point.UnmarshalCompressed(concatenatedData)
	return point, err
}

func (v VRFStruct) gammaToHash(point *AffinePoint) ([]byte, error) {
	// Step 6: Compute beta
	// betaString = Hash(suiteString || proofToHashDomainSeparatorFront ||
	// 	pointToString(cofactor * Gamma) || proofToHashDomainSeparatorBack)

	// TO-DO cofactor
	// cofactor := 1 // Replace with the actual cofactor value
	// point := gamma.mul(cofactor)

	var data []byte
	data = append(data, v.SuiteID)
	data = append(data, proofToHashDSTFront)
	data = append(data, point.Bytes()...)
	data = append(data, proofToHashDSTBack)
	return v.Hash(data), nil
}
