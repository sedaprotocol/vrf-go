package vrf_secp256k1

import (
	"crypto/sha256"
	"errors"
)

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
	c_string := sha256.Sum256(pointBytes) // TO-DO use v's hasher

	// Step 7: truncated_c_string = c_string[0]...c_string[cLen-1]
	if truncateLen > len(c_string) {
		return nil, errors.New("truncate length exceeds hash length")
	}
	truncated_c_string := c_string[:truncateLen]

	// Step 8: c = string_to_int(truncated_c_string)
	// Note: not needed because `prove` and `verify` functions need bytes and scalar values
	return truncated_c_string, nil
}
