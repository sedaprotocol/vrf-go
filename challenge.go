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
	CFieldBytesSize := 32 // TO-DO
	cScalar = make([]byte, CFieldBytesSize-v.CLen)
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
	// for _, point := range points {
	// 	// TO-DO: The point_to_string function converts a point on E to an octet string according to the encoding specified in Section 2.3.3 of [SECG1] with point compression on.
	// 	pointBytes = append(pointBytes, point)
	// }

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
