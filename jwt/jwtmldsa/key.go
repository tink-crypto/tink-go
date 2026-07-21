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

package jwtmldsa

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

// PublicKey represents a public key for JWT ML-DSA signing.
type PublicKey struct {
	parameters    *Parameters
	keyBytes      []byte
	idRequirement uint32
	kid           string
	// True iif a custom KID was given or
	// parameters.KIDStrategy() == Base64EncodedKeyIDAsKID
	hasKID bool
}

var _ key.Key = (*PublicKey)(nil)

func computeKID(customKID string, hasCustomKID bool, idRequirement uint32, parameters *Parameters) (string, bool, error) {
	if !hasCustomKID && len(customKID) != 0 {
		return "", false, fmt.Errorf("hasCustomKID is false but customKID is not empty")
	}
	switch parameters.KIDStrategy() {
	case Base64EncodedKeyIDAsKID:
		if hasCustomKID {
			return "", false, fmt.Errorf("custom KID is not supported for KID strategy: %v", parameters.KIDStrategy())
		}
		// Serialize the ID requirement.
		idRequirementBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idRequirementBytes, idRequirement)
		return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(idRequirementBytes), true, nil
	case IgnoredKID:
		if hasCustomKID {
			return "", false, fmt.Errorf("custom KID is not supported for KID strategy: %v", parameters.KIDStrategy())
		}
		return "", false, nil
	case CustomKID:
		if !hasCustomKID {
			return "", false, fmt.Errorf("custom KID is required for KID strategy: %v", parameters.KIDStrategy())
		}
		return customKID, hasCustomKID, nil
	default:
		return "", false, fmt.Errorf("invalid KID strategy: %v", parameters.KIDStrategy())
	}
}

// PublicKeyOpts are [PublicKey] options.
type PublicKeyOpts struct {
	KeyBytes      []byte
	IDRequirement uint32
	CustomKID     string
	HasCustomKID  bool
	Parameters    *Parameters
}

func checkPublicKeyLengthForAlgorithm(length int, algorithm Algorithm) error {
	switch algorithm {
	case MLDSA44:
		expectedLength := mldsa.MLDSA44.PublicKeyLength()
		if length != expectedLength {
			return fmt.Errorf("public key length must be %d bytes", expectedLength)
		}
	case MLDSA65:
		expectedLength := mldsa.MLDSA65.PublicKeyLength()
		if length != expectedLength {
			return fmt.Errorf("public key length must be %d bytes", expectedLength)
		}
	case MLDSA87:
		expectedLength := mldsa.MLDSA87.PublicKeyLength()
		if length != expectedLength {
			return fmt.Errorf("public key length must be %d bytes", expectedLength)
		}
	default:
		return fmt.Errorf("invalid algorithm: %v", algorithm)
	}
	return nil
}

// NewPublicKey creates a new JWT ML-DSA public key.
func NewPublicKey(opts PublicKeyOpts) (*PublicKey, error) {
	if opts.Parameters == nil {
		return nil, fmt.Errorf("jwtmldsa.NewPublicKey: parameters can't be nil")
	}
	if !opts.Parameters.HasIDRequirement() && opts.IDRequirement != 0 {
		return nil, fmt.Errorf("jwtmldsa.NewPublicKey: ID requirement must be 0 if ID is not required")
	}
	if err := checkPublicKeyLengthForAlgorithm(len(opts.KeyBytes), opts.Parameters.Algorithm()); err != nil {
		return nil, fmt.Errorf("jwtmldsa.NewPublicKey: %w", err)
	}
	kid, hasKID, err := computeKID(opts.CustomKID, opts.HasCustomKID, opts.IDRequirement, opts.Parameters)
	if err != nil {
		return nil, fmt.Errorf("jwtmldsa.NewPublicKey: %v", err)
	}
	return &PublicKey{
		parameters:    opts.Parameters,
		keyBytes:      bytes.Clone(opts.KeyBytes),
		idRequirement: opts.IDRequirement,
		kid:           kid,
		hasKID:        hasKID,
	}, nil
}

// Parameters returns the parameters of the key.
func (k *PublicKey) Parameters() key.Parameters { return k.parameters }

// KeyBytes returns the public key bytes.
func (k *PublicKey) KeyBytes() []byte { return bytes.Clone(k.keyBytes) }

// KID returns the KID for this key.
//
// If no kid is set, it returns ("", false).
func (k *PublicKey) KID() (string, bool) { return k.kid, k.hasKID }

// IDRequirement returns the ID requirement for this key.
func (k *PublicKey) IDRequirement() (uint32, bool) {
	return k.idRequirement, k.parameters.HasIDRequirement()
}

// Equal returns true if k and other are equal.
func (k *PublicKey) Equal(other key.Key) bool {
	that, ok := other.(*PublicKey)
	return ok && k.parameters.Equal(that.parameters) &&
		bytes.Equal(k.keyBytes, that.keyBytes) &&
		k.idRequirement == that.idRequirement &&
		k.kid == that.kid && k.hasKID == that.hasKID
}

// PrivateKey represents a JWT ML-DSA key.
type PrivateKey struct {
	publicKey       *PublicKey
	privateKeyBytes secretdata.Bytes
}

func keyGenForAlgorithm(seed secretdata.Bytes, algorithm Algorithm) ([]byte, error) {
	switch algorithm {
	case MLDSA44:
		var seedBytes [mldsa.SecretKeySeedSize]byte
		copy(seedBytes[:], seed.Data(insecuresecretdataaccess.Token{}))
		publicKey, _ := mldsa.MLDSA44.KeyGenFromSeed(seedBytes)
		return publicKey.Encode(), nil
	case MLDSA65:
		var seedBytes [mldsa.SecretKeySeedSize]byte
		copy(seedBytes[:], seed.Data(insecuresecretdataaccess.Token{}))
		publicKey, _ := mldsa.MLDSA65.KeyGenFromSeed(seedBytes)
		return publicKey.Encode(), nil
	case MLDSA87:
		var seedBytes [mldsa.SecretKeySeedSize]byte
		copy(seedBytes[:], seed.Data(insecuresecretdataaccess.Token{}))
		publicKey, _ := mldsa.MLDSA87.KeyGenFromSeed(seedBytes)
		return publicKey.Encode(), nil
	default:
		return nil, fmt.Errorf("invalid algorithm: %v", algorithm)
	}
}

// NewPrivateKeyFromPublicKey creates a new JWT ML-DSA private key.
func NewPrivateKeyFromPublicKey(keyBytes secretdata.Bytes, publicKey *PublicKey) (*PrivateKey, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("jwtmldsa.NewPrivateKeyFromPublicKey: public key can't be nil")
	}
	if keyBytes.Len() != mldsa.SecretKeySeedSize {
		return nil, fmt.Errorf("jwtmldsa.NewPrivateKeyFromPublicKey: private key seed length must be %d bytes", mldsa.SecretKeySeedSize)
	}
	pubKeyBytes, err := keyGenForAlgorithm(keyBytes, publicKey.parameters.Algorithm())
	if err != nil {
		return nil, fmt.Errorf("jwtmldsa.NewPrivateKeyFromPublicKey: %w", err)
	}
	if !bytes.Equal(publicKey.KeyBytes(), pubKeyBytes) {
		return nil, fmt.Errorf("jwtmldsa.NewPrivateKeyFromPublicKey: public key mismatch")
	}
	return &PrivateKey{
		publicKey:       publicKey,
		privateKeyBytes: keyBytes,
	}, nil
}

// Parameters returns the parameters of the key.
func (k *PrivateKey) Parameters() key.Parameters { return k.publicKey.Parameters() }

// PrivateKeyValue returns the private key seed material.
func (k *PrivateKey) PrivateKeyValue() secretdata.Bytes { return k.privateKeyBytes }

// PublicKey returns the public key.
func (k *PrivateKey) PublicKey() (key.Key, error) { return k.publicKey, nil }

// IDRequirement returns the ID requirement for this key.
func (k *PrivateKey) IDRequirement() (uint32, bool) { return k.publicKey.IDRequirement() }

// Equal returns true if k and other are equal.
func (k *PrivateKey) Equal(other key.Key) bool {
	that, ok := other.(*PrivateKey)
	return ok && k.publicKey.Equal(that.publicKey) &&
		k.privateKeyBytes.Equal(that.privateKeyBytes)
}

func createPrivateKey(p key.Parameters, idRequirement uint32) (key.Key, error) {
	jwtMLDSAParams, ok := p.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("jwtmldsa.createPrivateKey: invalid parameters type: want %T, got %T", (*Parameters)(nil), p)
	}
	if jwtMLDSAParams.KIDStrategy() == CustomKID {
		return nil, fmt.Errorf("jwtmldsa.createPrivateKey: key generation is not supported for strategy %v", jwtMLDSAParams.KIDStrategy())
	}
	seed, err := secretdata.NewBytesFromRand(mldsa.SecretKeySeedSize)
	if err != nil {
		return nil, fmt.Errorf("jwtmldsa.createPrivateKey: failed to generate random seed: %w", err)
	}
	pubKeyBytes, err := keyGenForAlgorithm(seed, jwtMLDSAParams.Algorithm())
	if err != nil {
		return nil, fmt.Errorf("jwtmldsa.createPrivateKey: %w", err)
	}
	publicKey, err := NewPublicKey(PublicKeyOpts{
		KeyBytes:      pubKeyBytes,
		IDRequirement: idRequirement,
		HasCustomKID:  false,
		Parameters:    jwtMLDSAParams,
	})
	if err != nil {
		return nil, fmt.Errorf("jwtmldsa.createPrivateKey: %v", err)
	}
	return NewPrivateKeyFromPublicKey(seed, publicKey)
}
