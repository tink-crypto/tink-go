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

package aesgcm

import (
	"bytes"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/outputprefix"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

// Variant is the prefix variant of AES-GCM keys.
//
// It describes how the prefix of the ciphertext is constructed. For AEAD there
// are three options:
//
// * TINK: prepends '0x01<big endian key id>' to the ciphertext.
// * CRUNCHY: prepends '0x00<big endian key id>' to the ciphertext.
// * NO_PREFIX: adds no prefix to the ciphertext.
type Variant int

const (
	// VariantUnknown is the default and invalid value of Variant.
	VariantUnknown Variant = iota
	// VariantTink prefixes '0x01<big endian key id>' to the ciphertext.
	VariantTink
	// VariantCrunchy prefixes '0x00<big endian key id>' to the ciphertext.
	VariantCrunchy
	// VariantNoPrefix adds no prefix to the ciphertext.
	VariantNoPrefix
)

func (variant Variant) String() string {
	switch variant {
	case VariantTink:
		return "TINK"
	case VariantCrunchy:
		return "CRUNCHY"
	case VariantNoPrefix:
		return "NO_PREFIX"
	default:
		return "UNKNOWN"
	}
}

// calculateOutputPrefix calculates the output prefix from keyID.
func calculateOutputPrefix(variant Variant, keyID uint32) ([]byte, error) {
	switch variant {
	case VariantTink:
		return outputprefix.Tink(keyID), nil
	case VariantCrunchy:
		return outputprefix.Legacy(keyID), nil
	case VariantNoPrefix:
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid output prefix variant: %v", variant)
	}
}

// Parameters specifies an AES-GCM key.
type Parameters struct {
	keySizeInBytes int
	ivSizeInBytes  int
	tagSizeInBytes int
	variant        Variant
}

var _ key.Parameters = (*Parameters)(nil)

// KeySizeInBytes returns the size of the key in bytes.
func (p *Parameters) KeySizeInBytes() int { return p.keySizeInBytes }

// IVSizeInBytes returns the size of the IV in bytes.
func (p *Parameters) IVSizeInBytes() int { return p.ivSizeInBytes }

// TagSizeInBytes returns the size of the tag in bytes.
func (p *Parameters) TagSizeInBytes() int { return p.tagSizeInBytes }

// Variant returns the variant of the key.
func (p *Parameters) Variant() Variant { return p.variant }

// ParametersOpts specifies options for creating AES-GCM parameters.
type ParametersOpts struct {
	KeySizeInBytes int
	IVSizeInBytes  int
	TagSizeInBytes int
	Variant        Variant
}

// NewParameters creates a new AES-GCM Parameters object.
func NewParameters(opts ParametersOpts) (*Parameters, error) {
	if opts.KeySizeInBytes != 16 && opts.KeySizeInBytes != 24 && opts.KeySizeInBytes != 32 {
		return nil, fmt.Errorf("aesgcm.Parameters: unsupported key size; want 16, 24, or 32, got: %v", opts.KeySizeInBytes)
	}
	if opts.IVSizeInBytes <= 0 {
		return nil, fmt.Errorf("aesgcm.Parameters: unsupported IV size; want > 0, got: %v", opts.IVSizeInBytes)
	}
	if opts.TagSizeInBytes < 12 || opts.TagSizeInBytes > 16 {
		return nil, fmt.Errorf("aesgcm.Parameters: unsupported tag size; want >= 12 and <= 16, got: %v", opts.TagSizeInBytes)
	}
	if opts.Variant == VariantUnknown {
		return nil, fmt.Errorf("aesgcm.Parameters: unsupported variant: %v", opts.Variant)
	}
	return &Parameters{
		keySizeInBytes: opts.KeySizeInBytes,
		ivSizeInBytes:  opts.IVSizeInBytes,
		tagSizeInBytes: opts.TagSizeInBytes,
		variant:        opts.Variant,
	}, nil
}

// HasIDRequirement returns whether the key has an ID requirement.
func (p *Parameters) HasIDRequirement() bool { return p.variant != VariantNoPrefix }

// Equals returns whether this Parameters object is equal to other.
func (p *Parameters) Equals(other key.Parameters) bool {
	actualParams, ok := other.(*Parameters)
	return ok && p.HasIDRequirement() == actualParams.HasIDRequirement() &&
		p.keySizeInBytes == actualParams.keySizeInBytes &&
		p.ivSizeInBytes == actualParams.ivSizeInBytes &&
		p.tagSizeInBytes == actualParams.tagSizeInBytes &&
		p.variant == actualParams.variant
}

// Key represents an AES-GCM key.
type Key struct {
	keyBytes     secretdata.Bytes
	id           uint32
	outputPrefix []byte
	parameters   *Parameters
}

var _ key.Key = (*Key)(nil)

// NewKey creates a new AES-GCM key with key, keyID and parameters.
func NewKey(keyBytes secretdata.Bytes, keyID uint32, parameters *Parameters) (*Key, error) {
	if parameters == nil {
		return nil, fmt.Errorf("aesgcm.NewKey: parameters is nil")
	}
	if keyBytes.Len() != int(parameters.KeySizeInBytes()) {
		return nil, fmt.Errorf("aesgcm.NewKey: key.Len() = %v, want %v", keyBytes.Len(), parameters.KeySizeInBytes())
	}
	outputPrefix, err := calculateOutputPrefix(parameters.Variant(), keyID)
	if err != nil {
		return nil, fmt.Errorf("aesgcm.NewKey: %v", err)
	}
	return &Key{
		keyBytes:     keyBytes,
		id:           keyID,
		outputPrefix: outputPrefix,
		parameters:   parameters,
	}, nil
}

// KeyBytes returns the key material.
//
// This function provides access to partial key material. See
// https://developers.google.com/tink/design/access_control#access_of_parts_of_a_key
// for more information.
func (k *Key) KeyBytes() secretdata.Bytes { return k.keyBytes }

// Parameters returns the parameters of this key.
func (k *Key) Parameters() key.Parameters { return k.parameters }

// IDRequirement returns whether the key ID and whether it is required
//
// If not required, the returned key ID is not usable.
func (k *Key) IDRequirement() (uint32, bool) { return k.id, k.Parameters().HasIDRequirement() }

// OutputPrefix returns the output prefix.
func (k *Key) OutputPrefix() []byte { return bytes.Clone(k.outputPrefix) }

// Equals returns whether this key object is equal to other.
func (k *Key) Equals(other key.Key) bool {
	that, ok := other.(*Key)
	return ok && k.Parameters().Equals(that.Parameters()) &&
		k.id == that.id &&
		k.keyBytes.Equals(&that.keyBytes) &&
		bytes.Equal(k.outputPrefix, that.outputPrefix)
}
