// Copyright 2026 Google LLC
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

package compositemldsa

import (
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"
)

// Variant is the prefix variant of a ML-DSA key.
//
// It describes the format of the signature. For ML-DSA, there are two options:
//
//   - TINK: prepends '0x01<big endian key id>' to the signature.
//   - NO_PREFIX: adds no prefix to the signature.
type Variant int

const (
	// VariantUnknown is the default value of Variant.
	VariantUnknown Variant = iota
	// VariantTink prefixes '0x01<big endian key id>' to the signature.
	VariantTink
	// VariantNoPrefix does not prefix the signature with the key id.
	VariantNoPrefix
)

// MLDSAInstance is the instance type of the ML-DSA key.
type MLDSAInstance int

const (
	// UnknownInstance is the default value of MLDSAInstance.
	UnknownInstance MLDSAInstance = iota
	// MLDSA65 yields ML-DSA-65 parameters.
	MLDSA65
	// MLDSA87 yields ML-DSA-87 parameters.
	MLDSA87
)

// ClassicalAlgorithm is the description of the classical algorithm. Only the following algorithms are
// supported at the moment:
//
// - Ed25519
// - ECDSA with P256, P384, and P521
// - RSA-PSS with 3072 and 4096 bit keys
// - RSA-PKCS1 with 3072 and 4096 bit keys
type ClassicalAlgorithm int

const (
	// UnknownAlgorithm is the default value of ClassicalAlgorithm.
	UnknownAlgorithm ClassicalAlgorithm = iota
	// Ed25519 is the Ed25519 algorithm.
	Ed25519
	// ECDSAP256 is the ECDSA-P256 algorithm.
	ECDSAP256
	// ECDSAP384 is the ECDSA-P384 algorithm.
	ECDSAP384
	// ECDSAP521 is the ECDSA-P521 algorithm.
	ECDSAP521
	// RSA3072PSS is the RSA-3072-PSS algorithm.
	RSA3072PSS
	// RSA4096PSS is the RSA-4096-PSS algorithm.
	RSA4096PSS
	// RSA3072PKCS1 is the RSA-3072-PKCS1 algorithm.
	RSA3072PKCS1
	// RSA4096PKCS1 is the RSA-4096-PKCS1 algorithm.
	RSA4096PKCS1
)

// Parameters represents the parameters of a composite ML-DSA key.
type Parameters struct {
	classicalAlgorithm ClassicalAlgorithm
	mldsaInstance      MLDSAInstance
	variant            Variant
}

// NewParameters creates a new Parameters.
func NewParameters(classicalAlgorithm ClassicalAlgorithm, mldsaInstance MLDSAInstance, variant Variant) (*Parameters, error) {
	if variant == VariantUnknown {
		return nil, errors.New("variant cannot be VariantUnknown")
	}

	switch mldsaInstance {
	// Supported combinations are defined at https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-15#name-algorithm-identifiers-and-p.
	case MLDSA65:
		switch classicalAlgorithm {
		// Supported combination
		case Ed25519, ECDSAP256, ECDSAP384, RSA3072PSS, RSA4096PSS, RSA3072PKCS1, RSA4096PKCS1:
		default:
			return nil, fmt.Errorf("unsupported classical algorithm for ML-DSA-65: %v", classicalAlgorithm)
		}
	case MLDSA87:
		switch classicalAlgorithm {
		// Supported combination
		case ECDSAP384, ECDSAP521, RSA3072PSS, RSA4096PSS:
		default:
			return nil, fmt.Errorf("unsupported classical algorithm for ML-DSA-87: %v", classicalAlgorithm)
		}
	default:
		return nil, fmt.Errorf("unsupported ML-DSA instance: %v", mldsaInstance)
	}

	return &Parameters{classicalAlgorithm: classicalAlgorithm, mldsaInstance: mldsaInstance, variant: variant}, nil
}

var _ key.Parameters = (*Parameters)(nil)

// ClassicalAlgorithm returns the classical algorithm variant of the parameters.
func (p *Parameters) ClassicalAlgorithm() ClassicalAlgorithm { return p.classicalAlgorithm }

// HasIDRequirement returns true if the key has an ID requirement.
func (p *Parameters) HasIDRequirement() bool { return p.variant != VariantNoPrefix }

// Variant returns the prefix variant of the parameters.
func (p *Parameters) Variant() Variant { return p.variant }

// Equal returns true if this parameters object is equal to other.
func (p *Parameters) Equal(other key.Parameters) bool {
	then, ok := other.(*Parameters)
	return ok && p.classicalAlgorithm == then.classicalAlgorithm &&
		p.mldsaInstance == then.mldsaInstance &&
		p.variant == then.variant
}

// MLDSAInstance returns the ML-DSA instance of the parameters.
func (p *Parameters) MLDSAInstance() MLDSAInstance { return p.mldsaInstance }

func instanceFromMlDsaInstance(mldsaInstance mldsa.Instance) (MLDSAInstance, error) {
	switch mldsaInstance {
	case mldsa.MLDSA65:
		return MLDSA65, nil
	case mldsa.MLDSA87:
		return MLDSA87, nil
	default:
		return UnknownInstance, fmt.Errorf("unsupported ML-DSA instance: %v", mldsaInstance)
	}
}

func variantFromMlDsaVariant(mldsaVariant mldsa.Variant) (Variant, error) {
	switch mldsaVariant {
	case mldsa.VariantTink:
		return VariantTink, nil
	case mldsa.VariantNoPrefix:
		return VariantNoPrefix, nil
	default:
		return VariantUnknown, fmt.Errorf("unsupported ML-DSA variant: %v", mldsaVariant)
	}
}
