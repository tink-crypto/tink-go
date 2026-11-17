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

package keytest

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

// AsymmetricParameters specifies the parameters of a test-only public or
// private key.
type AsymmetricParameters struct {
	variant Variant
}

var _ key.Parameters = (*AsymmetricParameters)(nil)

// NewAsymmetricParameters creates a new test-only AsymmetricParameters object.
func NewAsymmetricParameters(variant Variant) (*AsymmetricParameters, error) {
	if variant == VariantUnknown {
		return nil, fmt.Errorf("keytest.NewAsymmetricParameters: invalid variant: %v", variant)
	}
	return &AsymmetricParameters{
		variant: variant,
	}, nil
}

// Variant returns the variant of the key.
func (p *AsymmetricParameters) Variant() Variant { return p.variant }

// HasIDRequirement returns whether the key has an ID requirement.
func (p *AsymmetricParameters) HasIDRequirement() bool {
	return p.variant != VariantNoPrefix && p.variant != VariantUnknown
}

// Equal returns whether this AsymmetricParameters object is equal to other.
func (p *AsymmetricParameters) Equal(other key.Parameters) bool {
	that, ok := other.(*AsymmetricParameters)
	return ok && that != nil && p.variant == that.variant
}

// PublicKey represents a test-only public key.
//
// The public key bytes are the private key bytes in reverse order, so anyone
// can compute the private key from the public key. This key provides no
// security at all and must only be used in tests.
type PublicKey struct {
	keyBytes []byte
	// idRequirement is the ID requirement of the key. If the key is in a keyset
	// and the key has an ID requirement, this matches the keyset key ID.
	idRequirement uint32
	outputPrefix  []byte
	parameters    AsymmetricParameters
}

var _ key.Key = (*PublicKey)(nil)

// NewPublicKey creates a new test-only public key with the given key bytes, ID
// requirement and parameters.
//
// keyBytes must be keySizeInBytes long. If parameters has no ID requirement,
// idRequirement must be 0.
func NewPublicKey(keyBytes []byte, idRequirement uint32, parameters *AsymmetricParameters) (*PublicKey, error) {
	if parameters == nil {
		return nil, fmt.Errorf("keytest.NewPublicKey: parameters is nil")
	}
	if idRequirement == 0 && parameters.HasIDRequirement() {
		return nil, fmt.Errorf("keytest.NewPublicKey: idRequirement is 0 but parameters has ID requirement")
	}
	if !parameters.HasIDRequirement() && idRequirement != 0 {
		return nil, fmt.Errorf("keytest.NewPublicKey: idRequirement = %v and parameters.HasIDRequirement() = false, want 0", idRequirement)
	}
	if len(keyBytes) != keySizeInBytes {
		return nil, fmt.Errorf("keytest.NewPublicKey: len(keyBytes) = %v, want %v", len(keyBytes), keySizeInBytes)
	}
	outputPrefix, err := calculateOutputPrefix(parameters.variant, idRequirement)
	if err != nil {
		return nil, fmt.Errorf("keytest.NewPublicKey: %v", err)
	}
	return &PublicKey{
		keyBytes:      bytes.Clone(keyBytes),
		idRequirement: idRequirement,
		outputPrefix:  outputPrefix,
		parameters:    *parameters,
	}, nil
}

// KeyBytes returns the public key bytes.
func (k *PublicKey) KeyBytes() []byte { return bytes.Clone(k.keyBytes) }

// Parameters returns the parameters of this key.
func (k *PublicKey) Parameters() key.Parameters { return &k.parameters }

// IDRequirement returns required to indicate if this key requires an
// identifier. If it does, id will contain that identifier.
func (k *PublicKey) IDRequirement() (uint32, bool) {
	return k.idRequirement, k.parameters.HasIDRequirement()
}

// OutputPrefix returns the output prefix.
func (k *PublicKey) OutputPrefix() []byte { return bytes.Clone(k.outputPrefix) }

// Equal returns whether this key object is equal to other.
func (k *PublicKey) Equal(other key.Key) bool {
	that, ok := other.(*PublicKey)
	return ok && that != nil &&
		k.parameters.Equal(&that.parameters) &&
		k.idRequirement == that.idRequirement &&
		bytes.Equal(k.keyBytes, that.keyBytes) &&
		bytes.Equal(k.outputPrefix, that.outputPrefix)
}

// PrivateKey represents a test-only private key.
//
// The corresponding public key bytes are the private key bytes in reverse
// order, so anyone can compute the private key from the public key. This key
// provides no security at all and must only be used in tests.
type PrivateKey struct {
	privateKeyBytes secretdata.Bytes
	// publicKey is nil only if the key was not created with [NewPrivateKey].
	publicKey *PublicKey
}

var _ key.Key = (*PrivateKey)(nil)

// publicKeyBytes returns the public key bytes that correspond to
// privateKeyBytes, that is, privateKeyBytes in reverse order.
func publicKeyBytes(privateKeyBytes secretdata.Bytes) []byte {
	b := privateKeyBytes.Data(insecuresecretdataaccess.Token{})
	slices.Reverse(b)
	return b
}

// NewPrivateKey creates a new test-only private key with the given private key
// bytes, ID requirement and parameters.
//
// privateKeyBytes must be keySizeInBytes long. If parameters has no ID
// requirement, idRequirement must be 0.
//
// The bytes of the corresponding public key are privateKeyBytes in reverse
// order.
func NewPrivateKey(privateKeyBytes secretdata.Bytes, idRequirement uint32, parameters *AsymmetricParameters) (*PrivateKey, error) {
	if parameters == nil {
		return nil, fmt.Errorf("keytest.NewPrivateKey: parameters is nil")
	}
	if privateKeyBytes.Len() != keySizeInBytes {
		return nil, fmt.Errorf("keytest.NewPrivateKey: privateKeyBytes.Len() = %v, want %v", privateKeyBytes.Len(), keySizeInBytes)
	}
	publicKey, err := NewPublicKey(publicKeyBytes(privateKeyBytes), idRequirement, parameters)
	if err != nil {
		return nil, fmt.Errorf("keytest.NewPrivateKey: %v", err)
	}
	return &PrivateKey{
		privateKeyBytes: privateKeyBytes,
		publicKey:       publicKey,
	}, nil
}

// PrivateKeyBytes returns the private key material.
//
// This function provides access to partial key material. See
// https://developers.google.com/tink/design/access_control#access_of_parts_of_a_key
// for more information.
func (k *PrivateKey) PrivateKeyBytes() secretdata.Bytes { return k.privateKeyBytes }

// PublicKey returns the public key of this key, which is a [*PublicKey].
//
// This implements the privateKey interface defined in keyset/handle.go.
func (k *PrivateKey) PublicKey() (key.Key, error) {
	if k.publicKey == nil {
		return nil, fmt.Errorf("keytest.PrivateKey: invalid key: public key is nil")
	}
	return k.publicKey, nil
}

// Parameters returns the parameters of this key.
func (k *PrivateKey) Parameters() key.Parameters {
	if k.publicKey == nil {
		return &AsymmetricParameters{}
	}
	return k.publicKey.Parameters()
}

// IDRequirement returns required to indicate if this key requires an
// identifier. If it does, id will contain that identifier.
func (k *PrivateKey) IDRequirement() (uint32, bool) {
	if k.publicKey == nil {
		return 0, false
	}
	return k.publicKey.IDRequirement()
}

// OutputPrefix returns the output prefix.
func (k *PrivateKey) OutputPrefix() []byte {
	if k.publicKey == nil {
		return nil
	}
	return k.publicKey.OutputPrefix()
}

// Equal returns whether this key object is equal to other.
func (k *PrivateKey) Equal(other key.Key) bool {
	that, ok := other.(*PrivateKey)
	if !ok || that == nil {
		return false
	}
	if k.publicKey == nil || that.publicKey == nil {
		return k.publicKey == nil && that.publicKey == nil &&
			k.privateKeyBytes.Equal(that.privateKeyBytes)
	}
	return k.publicKey.Equal(that.publicKey) &&
		k.privateKeyBytes.Equal(that.privateKeyBytes)
}

func createPrivateKey(p key.Parameters, idRequirement uint32) (key.Key, error) {
	testOnlyParams, ok := p.(*AsymmetricParameters)
	if !ok {
		return nil, fmt.Errorf("key is of type %T; needed *keytest.AsymmetricParameters", p)
	}
	privateKeyBytes, err := secretdata.NewBytesFromRand(uint32(keySizeInBytes))
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(privateKeyBytes, idRequirement, testOnlyParams)
}
