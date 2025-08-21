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

package jwtrsassapkcs1

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/tink-crypto/tink-go/v2/key"
)

// PublicKey represents a public key for JWT RSA SSA PKCS1 signing.
type PublicKey struct {
	parameters    *Parameters
	modulus       []byte // Big integer value in big-endian encoding.
	idRequirement uint32
	kid           string
	hasKID        bool
}

var _ key.Key = (*PublicKey)(nil)

func computeKID(customKID *string, idRequirement uint32, parameters *Parameters) (string, bool, error) {
	switch parameters.KIDStrategy() {
	case Base64EncodedKeyIDAsKID:
		if customKID != nil {
			return "", false, fmt.Errorf("custom KID is not supported for KID strategy: %v", parameters.KIDStrategy())
		}
		// Serialize the ID requirement.
		idRequirementBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idRequirementBytes, idRequirement)
		return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(idRequirementBytes), true, nil
	case IgnoredKID:
		if customKID != nil {
			return "", false, fmt.Errorf("custom KID is not supported for KID strategy: %v", parameters.KIDStrategy())
		}
		return "", false, nil
	case CustomKID:
		if customKID == nil {
			return "", false, fmt.Errorf("custom KID is required for KID strategy: %v", parameters.KIDStrategy())
		}
		return *customKID, true, nil
	default:
		return "", false, fmt.Errorf("invalid KID strategy: %v", parameters.KIDStrategy())
	}
}

// PublicKeyOpts are [PublicKey] options.
type PublicKeyOpts struct {
	Modulus       []byte
	IDRequirement uint32
	CustomKID     string
	HasCustomKID  bool
	Parameters    *Parameters
}

// NewPublicKey creates a new [PublicKey].
//
// The modulus is expected to be in big-endian encoding.
// The ID requirement must be 0 if the KID is not required.
func NewPublicKey(opts PublicKeyOpts) (*PublicKey, error) {
	if opts.Parameters == nil {
		return nil, fmt.Errorf("jwtrsassapkcs1.NewPublicKey: parameters can't be nil")
	}
	if !opts.Parameters.HasIDRequirement() && opts.IDRequirement != 0 {
		return nil, fmt.Errorf("jwtrsassapkcs1.NewPublicKey: ID requirement must be 0 if ID is not required")
	}
	if opts.Parameters.HasIDRequirement() && opts.IDRequirement == 0 {
		return nil, fmt.Errorf("jwtrsassapkcs1.NewPublicKey: ID requirement must not be 0 if ID is required")
	}

	modulusBigInt := new(big.Int).SetBytes(opts.Modulus)
	if modulusBigInt.BitLen() != opts.Parameters.ModulusSizeInBits() {
		return nil, fmt.Errorf("jwtrsassapkcs1.NewPublicKey: invalid modulus bit-length: %v, want %v", modulusBigInt.BitLen(), opts.Parameters.ModulusSizeInBits())
	}

	var customKID *string = nil
	if opts.HasCustomKID {
		customKID = &opts.CustomKID
	}
	kid, hasKID, err := computeKID(customKID, opts.IDRequirement, opts.Parameters)
	if err != nil {
		return nil, fmt.Errorf("jwtrsassapkcs1.NewPublicKey: %v", err)
	}
	return &PublicKey{
		parameters:    opts.Parameters,
		modulus:       opts.Modulus,
		idRequirement: opts.IDRequirement,
		kid:           kid,
		hasKID:        hasKID,
	}, nil
}

// Parameters returns the parameters of the key.
func (k *PublicKey) Parameters() key.Parameters { return k.parameters }

// Modulus returns the public key modulus.
func (k *PublicKey) Modulus() []byte { return bytes.Clone(k.modulus) }

// KID returns the KID for this key.
//
// If no kid is set, it returns ("", false).
func (k *PublicKey) KID() (string, bool) { return k.kid, k.hasKID }

// IDRequirement returns the ID requirement for this key.
func (k *PublicKey) IDRequirement() (uint32, bool) {
	return k.idRequirement, k.parameters.HasIDRequirement()
}

// Equal returns true if k and other are equal.
// Note that the comparison is not constant time.
func (k *PublicKey) Equal(other key.Key) bool {
	that, ok := other.(*PublicKey)
	return ok && k.parameters.Equal(that.parameters) &&
		bytes.Equal(k.modulus, that.modulus) &&
		k.idRequirement == that.idRequirement &&
		k.kid == that.kid && k.hasKID == that.hasKID
}
