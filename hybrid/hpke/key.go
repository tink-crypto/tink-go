// Copyright 2025 Google LLC
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

package hpke

import (
	"bytes"
	"crypto/ecdh"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/outputprefix"
	"github.com/tink-crypto/tink-go/v2/key"
)

// PublicKey represents an HPKE public key.
type PublicKey struct {
	// A public point representing the public key. This can be either:
	//  - Uncompressed encoded EC point as per [SEC 1 v2.0, Section 2.3.3] if Nist*.
	//  - An X25519 public key bytes.
	publicKeyBytes []byte
	idRequirement  uint32
	outputPrefix   []byte
	parameters     *Parameters
}

var _ key.Key = (*PublicKey)(nil)

func calculateOutputPrefix(variant Variant, idRequirement uint32) ([]byte, error) {
	switch variant {
	case VariantTink:
		return outputprefix.Tink(idRequirement), nil
	case VariantCrunchy:
		return outputprefix.Legacy(idRequirement), nil
	case VariantNoPrefix:
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid output prefix variant: %v", variant)
	}
}

func ecdhCurveFromKEMID(kemID KEMID) (ecdh.Curve, error) {
	switch kemID {
	case DHKEM_P256_HKDF_SHA256:
		return ecdh.P256(), nil
	case DHKEM_P384_HKDF_SHA384:
		return ecdh.P384(), nil
	case DHKEM_P521_HKDF_SHA512:
		return ecdh.P521(), nil
	case DHKEM_X25519_HKDF_SHA256:
		return ecdh.X25519(), nil
	default:
		return nil, fmt.Errorf("invalid KEMID: %v", kemID)
	}
}

// NewPublicKey creates a new HPKE PublicKey.
//
// publicKeyBytes belongs to either a NIST Curve or Curve25519.
func NewPublicKey(publicKeyBytes []byte, idRequirement uint32, parameters *Parameters) (*PublicKey, error) {
	if parameters.Variant() == VariantNoPrefix && idRequirement != 0 {
		return nil, fmt.Errorf("hpke.NewPublicKey: key ID must be zero for VariantNoPrefix")
	}
	outputPrefix, err := calculateOutputPrefix(parameters.Variant(), idRequirement)
	if err != nil {
		return nil, fmt.Errorf("hpke.NewPublicKey: %v", err)
	}
	curve, err := ecdhCurveFromKEMID(parameters.KEMID())
	if err != nil {
		return nil, fmt.Errorf("hpke.NewPublicKey: %v", err)
	}
	// Validate the point.
	if _, err := curve.NewPublicKey(publicKeyBytes); err != nil {
		return nil, fmt.Errorf("hpke.NewPublicKey: point validation failed: %v", err)
	}
	return &PublicKey{
		publicKeyBytes: bytes.Clone(publicKeyBytes),
		idRequirement:  idRequirement,
		outputPrefix:   outputPrefix,
		parameters:     parameters,
	}, nil
}

// PublicKeyBytes returns the public key bytes.
func (k *PublicKey) PublicKeyBytes() []byte { return k.publicKeyBytes }

// Parameters returns the parameters of this key.
func (k *PublicKey) Parameters() key.Parameters { return k.parameters }

// IDRequirement returns the key ID and whether it is required.
func (k *PublicKey) IDRequirement() (uint32, bool) {
	return k.idRequirement, k.Parameters().HasIDRequirement()
}

// OutputPrefix returns the output prefix of this key.
func (k *PublicKey) OutputPrefix() []byte { return bytes.Clone(k.outputPrefix) }

// Equal tells whether this key value is equal to other.
func (k *PublicKey) Equal(other key.Key) bool {
	otherKey, ok := other.(*PublicKey)
	return ok && k.Parameters().Equal(otherKey.Parameters()) &&
		k.idRequirement == otherKey.idRequirement &&
		bytes.Equal(k.publicKeyBytes, otherKey.publicKeyBytes)
}
