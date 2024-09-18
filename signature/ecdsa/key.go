// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecdsa

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/key"
)

// Variant is the prefix variant of an ECDSA key.
//
// It describes the format of the signature. For ECDSA there are four options:
//
//   - TINK: prepends '0x01<big endian key id>' to the signature.
//   - CRUNCHY: prepends '0x00<big endian key id>' to the signature.
//   - LEGACY: appends a 0-byte to the input message before computing the
//     signature, then prepends '0x00<big endian key id>' to the signature.
//   - NO_PREFIX: adds no prefix to the signature.
type Variant int

const (
	// VariantUnknown is the default value of Variant.
	VariantUnknown Variant = iota
	// VariantTink prefixes '0x01<big endian key id>' to the signature.
	VariantTink
	// VariantCrunchy prefixes '0x00<big endian key id>' to the signature.
	VariantCrunchy
	// VariantLegacy appends '0x00' to the input message BEFORE computing
	// the signature, then prepends '0x00<big endian key id>' to the signature.
	VariantLegacy
	// VariantNoPrefix does not prefix the signature with the key id.
	VariantNoPrefix
)

func (variant Variant) String() string {
	switch variant {
	case VariantTink:
		return "TINK"
	case VariantCrunchy:
		return "CRUNCHY"
	case VariantLegacy:
		return "LEGACY"
	case VariantNoPrefix:
		return "NO_PREFIX"
	default:
		return "UNKNOWN"
	}
}

// CurveType is the curve type of the ECDSA key.
type CurveType int

const (
	// UnknownCurveType is the default value of CurveType.
	UnknownCurveType CurveType = iota
	// NistP256 is the NIST P-256 curve.
	NistP256
	// NistP384 is the NIST P-384 curve.
	NistP384
	// NistP521 is the NIST P-521 curve.
	NistP521
)

func (ct CurveType) String() string {
	switch ct {
	case NistP256:
		return "NIST_P256"
	case NistP384:
		return "NIST_P384"
	case NistP521:
		return "NIST_P521"
	default:
		return "UNKNOWN"
	}
}

// HashType is the hash type of the ECDSA key.
type HashType int

const (
	// UnknownHashType is the default value of HashType.
	UnknownHashType HashType = iota
	// SHA256 is the SHA256 hash type.
	SHA256
	// SHA384 is the SHA384 hash type.
	SHA384
	// SHA512 is the SHA512 hash type.
	SHA512
)

func (ht HashType) String() string {
	switch ht {
	case SHA256:
		return "SHA256"
	case SHA384:
		return "SHA384"
	case SHA512:
		return "SHA512"
	default:
		return "UNKNOWN"
	}
}

// SignatureEncoding is the signature encoding of the ECDSA key.
type SignatureEncoding int

const (
	// UnknownSignatureEncoding is the default value of SignatureEncoding.
	UnknownSignatureEncoding SignatureEncoding = iota
	// DER is the DER encoding.
	DER
	// IEEEP1363 is the IEEE P1363 encoding.
	IEEEP1363
)

func (encoding SignatureEncoding) String() string {
	switch encoding {
	case DER:
		return "DER"
	case IEEEP1363:
		return "IEEE_P1363"
	default:
		return "UNKNOWN"
	}
}

// Parameters represents the parameters of an ECDSA key.
type Parameters struct {
	curveType         CurveType
	hashType          HashType
	signatureEncoding SignatureEncoding
	variant           Variant
}

var _ key.Parameters = (*Parameters)(nil)

// CurveType the curve type.
func (p *Parameters) CurveType() CurveType { return p.curveType }

// HashType returns the hash type.
func (p *Parameters) HashType() HashType { return p.hashType }

// SignatureEncoding returns the signature encoding.
func (p *Parameters) SignatureEncoding() SignatureEncoding { return p.signatureEncoding }

// Variant returns the output prefix variant of the key.
func (p *Parameters) Variant() Variant { return p.variant }

func checkValidHashForCurve(curveType CurveType, hashType HashType) error {
	switch curveType {
	case NistP256:
		if hashType != SHA256 {
			return fmt.Errorf("ecdsa.Parameters: unsupported hash type for curve type: %v, %v", curveType, hashType)
		}
	case NistP384:
		if hashType != SHA384 && hashType != SHA512 {
			return fmt.Errorf("ecdsa.Parameters: unsupported hash type for curve type: %v, %v", curveType, hashType)
		}
	case NistP521:
		if hashType != SHA512 {
			return fmt.Errorf("ecdsa.Parameters: unsupported hash type for curve type: %v, %v", curveType, hashType)
		}
	default:
		return fmt.Errorf("ecdsa.Parameters: unsupported curve type: %v", curveType)
	}
	return nil
}

func checkValidHash(hashType HashType) error {
	switch hashType {
	case SHA256, SHA384, SHA512:
		return nil
	default:
		return fmt.Errorf("unsupported hash type: %v", hashType)
	}
}

func checkValidSignatureEncoding(signatureEncoding SignatureEncoding) error {
	switch signatureEncoding {
	case DER, IEEEP1363:
		return nil
	default:
		return fmt.Errorf("unsupported signature encoding: %v", signatureEncoding)
	}
}

func checkValidVariant(variant Variant) error {
	switch variant {
	case VariantTink, VariantCrunchy, VariantLegacy, VariantNoPrefix:
		return nil
	default:
		return fmt.Errorf("unsupported output prefix variant: %v", variant)
	}
}

// NewParameters creates a new ECDSA Parameters object.
func NewParameters(curveType CurveType, hashType HashType, signatureEncoding SignatureEncoding, variant Variant) (*Parameters, error) {
	if err := checkValidHash(hashType); err != nil {
		return nil, fmt.Errorf("ecdsa.Parameters: %v", err)
	}
	if err := checkValidSignatureEncoding(signatureEncoding); err != nil {
		return nil, fmt.Errorf("ecdsa.Parameters: %v", err)
	}
	if err := checkValidVariant(variant); err != nil {
		return nil, fmt.Errorf("ecdsa.Parameters: %v", err)
	}
	if err := checkValidHashForCurve(curveType, hashType); err != nil {
		return nil, err
	}
	return &Parameters{
		curveType:         curveType,
		hashType:          hashType,
		signatureEncoding: signatureEncoding,
		variant:           variant,
	}, nil
}

// HasIDRequirement tells whether the key has an ID requirement.
func (p *Parameters) HasIDRequirement() bool { return p.variant != VariantNoPrefix }

// Equals tells whether this parameters object is equal to other.
func (p *Parameters) Equals(other key.Parameters) bool {
	actualParams, ok := other.(*Parameters)
	return ok && p.HasIDRequirement() == actualParams.HasIDRequirement() &&
		p.curveType == actualParams.curveType &&
		p.hashType == actualParams.hashType &&
		p.signatureEncoding == actualParams.signatureEncoding &&
		p.variant == actualParams.variant
}
