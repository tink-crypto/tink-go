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

package rsassapkcs1

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/key"
)

// Variant is the prefix variant of an RSA-SSA-PKCS1 key.
//
// It describes the format of the signature. For RSA-SSA-PKCS1 there are
// four options:
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
	// VariantLegacy appends a 0-byte to input message BEFORE computing the signature,
	// signature, then prepends '0x00<big endian key id>' to signature.
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

// HashType is the curve type of the RSA-SSA-PKCS1 key.
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

const (
	// f4 is the public exponent 65537.
	f4          = 65537
	maxExponent = 1<<31 - 1
)

// Parameters represents the parameters of an RSA-SSA-PKCS1 key.
type Parameters struct {
	modulusSizeBits int
	hashType        HashType
	publicExponent  int
	variant         Variant
}

var _ key.Parameters = (*Parameters)(nil)

// HashType returns the hash type.
func (p *Parameters) HashType() HashType { return p.hashType }

// PublicExponent returns the public exponent.
func (p *Parameters) PublicExponent() int { return p.publicExponent }

// ModulusSizeBits returns the modulus size in bits.
func (p *Parameters) ModulusSizeBits() int { return p.modulusSizeBits }

// Variant returns the output prefix variant of the key.
func (p *Parameters) Variant() Variant { return p.variant }

func checkValidHash(hashType HashType) error {
	if hashType == SHA256 || hashType == SHA384 || hashType == SHA512 {
		return nil
	}
	return fmt.Errorf("unsupported hash type: %v", hashType)
}

// NewParameters creates a new RSA-SSA-PKCS1 Parameters value.
func NewParameters(modulusSizeBits int, hashType HashType, publicExponent int, variant Variant) (*Parameters, error) {
	// These are consistent with the checks by tink-java and tink-cc.
	if modulusSizeBits < 2048 {
		return nil, fmt.Errorf("invalid modulus size: %v, want >= 2048", modulusSizeBits)
	}
	if publicExponent < f4 {
		return nil, fmt.Errorf("invalid public exponent: %v, want >= %v", publicExponent, f4)
	}
	// Similar check as in crypto/rsa.
	if publicExponent > maxExponent {
		return nil, fmt.Errorf("invalid public exponent: %v, want <= %v", publicExponent, maxExponent)
	}
	// These are consistent with the checks by tink-java and tink-cc.
	if publicExponent%2 != 1 {
		return nil, fmt.Errorf("invalid public exponent: %v, want odd", publicExponent)
	}
	if err := checkValidHash(hashType); err != nil {
		return nil, err
	}
	if variant == VariantUnknown {
		return nil, fmt.Errorf("unsupported output prefix variant: %v", variant)
	}
	return &Parameters{
		modulusSizeBits: modulusSizeBits,
		hashType:        hashType,
		publicExponent:  publicExponent,
		variant:         variant,
	}, nil
}

// HasIDRequirement tells whether the key has an ID requirement.
func (p *Parameters) HasIDRequirement() bool { return p.variant != VariantNoPrefix }

// Equals tells whether this parameters object is equal to other.
func (p *Parameters) Equals(other key.Parameters) bool {
	that, ok := other.(*Parameters)
	return ok && p.HasIDRequirement() == that.HasIDRequirement() &&
		p.modulusSizeBits == that.modulusSizeBits &&
		p.hashType == that.hashType &&
		p.publicExponent == that.publicExponent &&
		p.variant == that.variant
}
