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

// Package ed25519 provides ED25519 keys and parameters definitions.
package ed25519

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/key"
)

// Variant is the prefix variant of an ED25519 key.
//
// It describes the format of the signature. For ED25519, there are four options:
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

// Parameters represents the parameters of an ED25519 key.
type Parameters struct {
	variant Variant
}

var _ key.Parameters = (*Parameters)(nil)

// NewParameters creates a new Parameters.
func NewParameters(variant Variant) (Parameters, error) {
	if variant == VariantUnknown {
		return Parameters{}, fmt.Errorf("ed25519.NewParameters: variant must not be %v", VariantUnknown)
	}
	return Parameters{variant: variant}, nil
}

// Variant returns the prefix variant of the parameters.
func (p *Parameters) Variant() Variant { return p.variant }

// HasIDRequirement returns true if the key has an ID requirement.
func (p *Parameters) HasIDRequirement() bool { return p.variant != VariantNoPrefix }

// Equals returns true if this parameters object is equal to other.
func (p *Parameters) Equals(other key.Parameters) bool {
	if p == other {
		return true
	}
	then, ok := other.(*Parameters)
	return ok && p.variant == then.variant
}
