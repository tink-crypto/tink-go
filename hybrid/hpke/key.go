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
	"crypto/mlkem"
	"crypto/rand"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/hybrid/internal/xwing"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/outputprefix"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

const (
	xWingPublicKeySize     = 1216
	xWingSecretKeySize     = 32
	mlKEM768PublicKeySize  = 1184
	mlKEM768SecretKeySize  = 64
	mlKEM1024PublicKeySize = 1568
	mlKEM1024SecretKeySize = 64
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

func validateECDHPublicKey(publicKeyBytes []byte, kemID KEMID) error {
	curve, err := ecdhCurveFromKEMID(kemID)
	if err != nil {
		return fmt.Errorf("ecdhCurveFromKEMID failed: %w", err)
	}
	// Validate the point.
	if _, err := curve.NewPublicKey(publicKeyBytes); err != nil {
		return fmt.Errorf("point validation failed: %w", err)
	}
	return nil
}

func validateXWingPublicKey(publicKeyBytes []byte) error {
	if len(publicKeyBytes) != xWingPublicKeySize {
		return fmt.Errorf("invalid X-Wing public key length: %d, want %d", len(publicKeyBytes), xWingPublicKeySize)
	}
	return nil
}

func validateMLKEMPublicKey(publicKeyBytes []byte, kemID KEMID) error {
	switch kemID {
	case ML_KEM768:
		if len(publicKeyBytes) != mlKEM768PublicKeySize {
			return fmt.Errorf("invalid ML-KEM-768 public key length: %d, want %d", len(publicKeyBytes), mlKEM768PublicKeySize)
		}
	case ML_KEM1024:
		if len(publicKeyBytes) != mlKEM1024PublicKeySize {
			return fmt.Errorf("invalid ML-KEM-1024 public key length: %d, want %d", len(publicKeyBytes), mlKEM1024PublicKeySize)
		}
	default:
		return fmt.Errorf("invalid KEMID: %v", kemID)
	}
	return nil
}

func newECDHPublicKeyFromPrivateKey(privateKeyBytes secretdata.Bytes, kemID KEMID) ([]byte, error) {
	curve, err := ecdhCurveFromKEMID(kemID)
	if err != nil {
		return nil, err
	}
	ecdhPrivateKey, err := curve.NewPrivateKey(privateKeyBytes.Data(insecuresecretdataaccess.Token{}))
	if err != nil {
		return nil, fmt.Errorf("private key validation failed: %w", err)
	}
	return ecdhPrivateKey.PublicKey().Bytes(), nil
}

func newXWingPublicKeyFromPrivateKey(privateKeyBytes secretdata.Bytes) ([]byte, error) {
	publicKeyBytes, err := xwing.PublicFromSecret(privateKeyBytes.Data(insecuresecretdataaccess.Token{}))
	if err != nil {
		return nil, fmt.Errorf("xwing.PublicFromSecret failed: %w", err)
	}
	return publicKeyBytes, nil
}

func newMLKEMPublicKeyFromPrivateKey(privateKeyBytes secretdata.Bytes, kemID KEMID) ([]byte, error) {
	switch kemID {
	case ML_KEM768:
		privateKey, err := mlkem.NewDecapsulationKey768(privateKeyBytes.Data(insecuresecretdataaccess.Token{}))
		if err != nil {
			return nil, fmt.Errorf("mlkem.NewDecapsulationKey768 failed: %w", err)
		}
		return privateKey.EncapsulationKey().Bytes(), nil
	case ML_KEM1024:
		privateKey, err := mlkem.NewDecapsulationKey1024(privateKeyBytes.Data(insecuresecretdataaccess.Token{}))
		if err != nil {
			return nil, fmt.Errorf("mlkem.NewDecapsulationKey1024 failed: %w", err)
		}
		return privateKey.EncapsulationKey().Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported KEMID: %v", kemID)
	}
}

func validateECDHPrivateKey(privateKeyBytes secretdata.Bytes, pubKey *PublicKey) error {
	curve, err := ecdhCurveFromKEMID(pubKey.Parameters().(*Parameters).KEMID())
	if err != nil {
		return fmt.Errorf("ecdhCurveFromKEMID failed: %w", err)
	}
	ecdhPrivateKey, err := curve.NewPrivateKey(privateKeyBytes.Data(insecuresecretdataaccess.Token{}))
	if err != nil {
		return fmt.Errorf("private key validation failed: %w", err)
	}
	ecdhPublicKeyFromPrivateKey, err := curve.NewPublicKey(pubKey.publicKeyBytes)
	if err != nil {
		// Should never happen.
		return fmt.Errorf("invalid public key point: %w", err)
	}
	if !ecdhPrivateKey.PublicKey().Equal(ecdhPublicKeyFromPrivateKey) {
		return fmt.Errorf("invalid private key value")
	}
	return nil
}

func validateXWingPrivateKey(privateKeyBytes secretdata.Bytes, pubKey *PublicKey) error {
	xWingPublicKeyBytes, err := xwing.PublicFromSecret(privateKeyBytes.Data(insecuresecretdataaccess.Token{}))
	if err != nil {
		return fmt.Errorf("xwing.PublicFromSecret failed: %w", err)
	}
	if !bytes.Equal(xWingPublicKeyBytes, pubKey.publicKeyBytes) {
		return fmt.Errorf("invalid private key value")
	}
	return nil
}

func validateMLKEMPrivateKey(privateKeyBytes secretdata.Bytes, pubKey *PublicKey) error {
	switch pubKey.Parameters().(*Parameters).KEMID() {
	case ML_KEM768:
		mlKemPrivateKey, err := mlkem.NewDecapsulationKey768(privateKeyBytes.Data(insecuresecretdataaccess.Token{}))
		if err != nil {
			return fmt.Errorf("mlkem.NewDecapsulationKey768 failed: %w", err)
		}
		mlKemPublicKeyBytes := mlKemPrivateKey.EncapsulationKey().Bytes()
		if !bytes.Equal(mlKemPublicKeyBytes, pubKey.publicKeyBytes) {
			return fmt.Errorf("invalid private key value")
		}
	case ML_KEM1024:
		mlKemPrivateKey, err := mlkem.NewDecapsulationKey1024(privateKeyBytes.Data(insecuresecretdataaccess.Token{}))
		if err != nil {
			return fmt.Errorf("mlkem.NewDecapsulationKey1024 failed: %w", err)
		}
		mlKemPublicKeyBytes := mlKemPrivateKey.EncapsulationKey().Bytes()
		if !bytes.Equal(mlKemPublicKeyBytes, pubKey.publicKeyBytes) {
			return fmt.Errorf("invalid private key value")
		}
	default:
		return fmt.Errorf("unsupported KEMID: %v", pubKey.Parameters().(*Parameters).KEMID())
	}
	return nil
}

// NewPublicKey creates a new HPKE PublicKey.
//
// publicKeyBytes belongs to either a NIST Curve, Curve25519, X-Wing, ML-KEM-768 or ML-KEM-1024.
func NewPublicKey(publicKeyBytes []byte, idRequirement uint32, parameters *Parameters) (*PublicKey, error) {
	if parameters.Variant() == VariantNoPrefix && idRequirement != 0 {
		return nil, fmt.Errorf("hpke.NewPublicKey: key ID must be zero for VariantNoPrefix")
	}
	outputPrefix, err := calculateOutputPrefix(parameters.Variant(), idRequirement)
	if err != nil {
		return nil, fmt.Errorf("hpke.NewPublicKey: %w", err)
	}
	switch parameters.KEMID() {
	case DHKEM_P256_HKDF_SHA256, DHKEM_P384_HKDF_SHA384, DHKEM_P521_HKDF_SHA512, DHKEM_X25519_HKDF_SHA256:
		if err := validateECDHPublicKey(publicKeyBytes, parameters.KEMID()); err != nil {
			return nil, fmt.Errorf("hpke.NewPublicKey: validateECDHPublicKey failed: %w", err)
		}
	case X_WING:
		if err := validateXWingPublicKey(publicKeyBytes); err != nil {
			return nil, fmt.Errorf("hpke.NewPublicKey: validateXWingPublicKey failed: %w", err)
		}
	case ML_KEM768, ML_KEM1024:
		if err := validateMLKEMPublicKey(publicKeyBytes, parameters.KEMID()); err != nil {
			return nil, fmt.Errorf("hpke.NewPublicKey: validateMLKEMPublicKey failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("hpke.NewPublicKey: unsupported KEMID: %v", parameters.KEMID())
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

// PrivateKey represents an HPKE private key.
type PrivateKey struct {
	publicKey       *PublicKey
	privateKeyBytes secretdata.Bytes
}

var _ key.Key = (*PrivateKey)(nil)

// NewPrivateKey creates a new HPKE private key from privateKeyBytes,
// idRequirement and a [Parameters].
//
// If X25519 curve is used, the private key value must be 32 bytes.
// If NIST curve is used, the private key value must be octet encoded as per
// [SEC 1 v2.0, Section 2.3.5].
// If X-Wing is used, the private key value must be 32 bytes.
// If ML-KEM-768 is used, the private key value must be 64 bytes.
// If ML-KEM-1024 is used, the private key value must be 64 bytes.
//
// [SEC 1 v2.0, Section 2.3.5]: https://www.secg.org/sec1-v2.pdf#page=17.08
func NewPrivateKey(privateKeyBytes secretdata.Bytes, idRequirement uint32, params *Parameters) (*PrivateKey, error) {
	var publicKeyBytes []byte
	var err error
	switch params.KEMID() {
	case DHKEM_P256_HKDF_SHA256, DHKEM_P384_HKDF_SHA384, DHKEM_P521_HKDF_SHA512, DHKEM_X25519_HKDF_SHA256:
		publicKeyBytes, err = newECDHPublicKeyFromPrivateKey(privateKeyBytes, params.KEMID())
		if err != nil {
			return nil, fmt.Errorf("hpke.NewPrivateKey: newECDHPublicKeyFromPrivateKey failed: %w", err)
		}
	case X_WING:
		publicKeyBytes, err = newXWingPublicKeyFromPrivateKey(privateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("hpke.NewPrivateKey: newXWingPublicKeyFromPrivateKey failed: %w", err)
		}
	case ML_KEM768, ML_KEM1024:
		publicKeyBytes, err = newMLKEMPublicKeyFromPrivateKey(privateKeyBytes, params.KEMID())
		if err != nil {
			return nil, fmt.Errorf("hpke.NewPrivateKey: newMLKEMPublicKeyFromPrivateKey failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("hpke.NewPrivateKey: unsupported KEMID: %v", params.KEMID())
	}
	publicKey, err := NewPublicKey(publicKeyBytes, idRequirement, params)
	if err != nil {
		return nil, fmt.Errorf("hpke.NewPrivateKey: NewPublicKey failed: %w", err)
	}
	return &PrivateKey{
		publicKey:       publicKey,
		privateKeyBytes: privateKeyBytes,
	}, nil
}

// NewPrivateKeyFromPublicKey creates a new HPKE private key from
// privateKeyBytes and a [PublicKey].
//
// If X25519 curve is used, the private key value must be 32 bytes.
// If NIST curve is used, the private key value must be octet encoded as per
// [SEC 1 v2.0, Section 2.3.5].
// If X-Wing is used, the private key value must be 32 bytes.
// If ML-KEM-768 is used, the private key value must be 64 bytes.
// If ML-KEM-1024 is used, the private key value must be 64 bytes.
//
// [SEC 1 v2.0, Section 2.3.5]: https://www.secg.org/sec1-v2.pdf#page=17.08
func NewPrivateKeyFromPublicKey(privateKeyBytes secretdata.Bytes, pubKey *PublicKey) (*PrivateKey, error) {
	switch pubKey.Parameters().(*Parameters).KEMID() {
	case DHKEM_P256_HKDF_SHA256, DHKEM_P384_HKDF_SHA384, DHKEM_P521_HKDF_SHA512, DHKEM_X25519_HKDF_SHA256:
		if err := validateECDHPrivateKey(privateKeyBytes, pubKey); err != nil {
			return nil, fmt.Errorf("hpke.NewPrivateKeyFromPublicKey: validateECDHPrivateKey failed: %w", err)
		}
	case X_WING:
		if err := validateXWingPrivateKey(privateKeyBytes, pubKey); err != nil {
			return nil, fmt.Errorf("hpke.NewPrivateKeyFromPublicKey: validateXWingPrivateKey failed: %w", err)
		}
	case ML_KEM768, ML_KEM1024:
		if err := validateMLKEMPrivateKey(privateKeyBytes, pubKey); err != nil {
			return nil, fmt.Errorf("hpke.NewPrivateKeyFromPublicKey: validateMLKEMPrivateKey failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("hpke.NewPrivateKeyFromPublicKey: unsupported KEMID: %v", pubKey.Parameters().(*Parameters).KEMID())
	}
	return &PrivateKey{
		publicKey:       pubKey,
		privateKeyBytes: privateKeyBytes,
	}, nil
}

// PrivateKeyBytes returns the private key bytes.
func (k *PrivateKey) PrivateKeyBytes() secretdata.Bytes { return k.privateKeyBytes }

// PublicKey returns the public key of the key.
//
// This implements the privateKey interface defined in handle.go.
func (k *PrivateKey) PublicKey() (key.Key, error) { return k.publicKey, nil }

// Parameters returns the parameters of the key.
func (k *PrivateKey) Parameters() key.Parameters { return k.publicKey.Parameters() }

// IDRequirement returns the ID requirement of the key, and whether it is
// required.
func (k *PrivateKey) IDRequirement() (uint32, bool) { return k.publicKey.IDRequirement() }

// OutputPrefix returns the output prefix of this key.
func (k *PrivateKey) OutputPrefix() []byte { return bytes.Clone(k.publicKey.outputPrefix) }

// Equal returns true if this key is equal to other.
func (k *PrivateKey) Equal(other key.Key) bool {
	otherKey, ok := other.(*PrivateKey)
	return ok && k.publicKey.Equal(otherKey.publicKey) &&
		k.privateKeyBytes.Equal(otherKey.privateKeyBytes)
}

func createPrivateKey(p key.Parameters, idRequirement uint32) (key.Key, error) {
	hpkeParams, ok := p.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: %T, want %T", p, (*Parameters)(nil))
	}
	var privKeyBytes secretdata.Bytes
	var err error
	switch hpkeParams.KEMID() {
	case DHKEM_P256_HKDF_SHA256, DHKEM_P384_HKDF_SHA384, DHKEM_P521_HKDF_SHA512, DHKEM_X25519_HKDF_SHA256:
		curve, err := ecdhCurveFromKEMID(hpkeParams.KEMID())
		if err != nil {
			return nil, err
		}
		privKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		privKeyBytes = secretdata.NewBytesFromData(privKey.Bytes(), insecuresecretdataaccess.Token{})
	case X_WING:
		privKeyBytes, err = secretdata.NewBytesFromRand(xWingSecretKeySize)
		if err != nil {
			return nil, err
		}
	case ML_KEM768:
		privKeyBytes, err = secretdata.NewBytesFromRand(mlKEM768SecretKeySize)
		if err != nil {
			return nil, err
		}
	case ML_KEM1024:
		privKeyBytes, err = secretdata.NewBytesFromRand(mlKEM1024SecretKeySize)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported KEMID: %v", hpkeParams.KEMID())
	}
	return NewPrivateKey(privKeyBytes, idRequirement, hpkeParams)
}
