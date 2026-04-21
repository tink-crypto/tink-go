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
	"bytes"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/outputprefix"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
)

const (
	// f4 is the public exponent 65537.
	f4 = 65537
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
	mlDSAInstance      MLDSAInstance
	variant            Variant
}

type mlDSAAndClassicalInstance struct {
	classicalAlgorithm ClassicalAlgorithm
	mlDSAInstance      MLDSAInstance
}

// supportedParameterSets is a set of supported parameter set combinations.
// Supported combinations are defined at https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-15#name-algorithm-identifiers-and-p.
var supportedParameterSets = map[mlDSAAndClassicalInstance]struct{}{
	// MLDSA65
	{Ed25519, MLDSA65}:      struct{}{},
	{ECDSAP256, MLDSA65}:    struct{}{},
	{ECDSAP384, MLDSA65}:    struct{}{},
	{RSA3072PSS, MLDSA65}:   struct{}{},
	{RSA4096PSS, MLDSA65}:   struct{}{},
	{RSA3072PKCS1, MLDSA65}: struct{}{},
	{RSA4096PKCS1, MLDSA65}: struct{}{},
	// MLDSA87
	{ECDSAP384, MLDSA87}:  struct{}{},
	{ECDSAP521, MLDSA87}:  struct{}{},
	{RSA3072PSS, MLDSA87}: struct{}{},
	{RSA4096PSS, MLDSA87}: struct{}{},
}

// NewParameters creates a new Parameters.
func NewParameters(classicalAlgorithm ClassicalAlgorithm, mlDSAInstance MLDSAInstance, variant Variant) (*Parameters, error) {
	if variant == VariantUnknown {
		return nil, fmt.Errorf("variant must be specified")
	}
	key := mlDSAAndClassicalInstance{classicalAlgorithm, mlDSAInstance}
	if _, supported := supportedParameterSets[key]; !supported {
		return nil, fmt.Errorf("unsupported parameter combination: {ClassicalAlgorithm: %v, MLDSAInstance: %v}", classicalAlgorithm, mlDSAInstance)
	}
	return &Parameters{classicalAlgorithm: classicalAlgorithm, mlDSAInstance: mlDSAInstance, variant: variant}, nil
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
		p.mlDSAInstance == then.mlDSAInstance &&
		p.variant == then.variant
}

// MLDSAInstance returns the ML-DSA instance of the parameters.
func (p *Parameters) MLDSAInstance() MLDSAInstance { return p.mlDSAInstance }

// PublicKey represents a composite ML-DSA public key.
// The classical public key must be of one of the following concrete types:
//
//   - ed25519.PublicKey
//   - ecdsa.PublicKey
//   - rsassapss.PublicKey: in this case, modulus should be 3072 or 4096 bits.
//   - rsassapkcs1.PublicKey: in this case, modulus should be 3072 or 4096 bits.
type PublicKey struct {
	mlDSAPublicKey     *mldsa.PublicKey
	classicalPublicKey key.Key
	params             *Parameters
	idRequirement      uint32
	outputPrefix       []byte
}

var _ key.Key = (*PublicKey)(nil)

// Parameters returns the parameters of the key.
func (k *PublicKey) Parameters() key.Parameters { return k.params }

// IDRequirement returns the ID requirement of the key, and whether it is
// required.
func (k *PublicKey) IDRequirement() (uint32, bool) {
	return k.idRequirement, k.params.HasIDRequirement()
}

// OutputPrefix returns the output prefix of the key.
func (k *PublicKey) OutputPrefix() []byte {
	return k.outputPrefix
}

// ClassicalPublicKey returns the classical public key.
func (k *PublicKey) ClassicalPublicKey() key.Key {
	return k.classicalPublicKey
}

// MLDSAPublicKey returns the ML-DSA public key.
func (k *PublicKey) MLDSAPublicKey() *mldsa.PublicKey {
	return k.mlDSAPublicKey
}

// Equal returns true if this key is equal to other.
func (k *PublicKey) Equal(other key.Key) bool {
	if k == other {
		return true
	}
	that, ok := other.(*PublicKey)
	return ok && k.params.Equal(that.Parameters()) &&
		bytes.Equal(k.mlDSAPublicKey.KeyBytes(), that.mlDSAPublicKey.KeyBytes()) &&
		k.classicalPublicKey.Equal(that.classicalPublicKey) &&
		k.idRequirement == that.idRequirement
}

func calculateOutputPrefix(variant Variant, keyID uint32) ([]byte, error) {
	switch variant {
	case VariantTink:
		return outputprefix.Tink(keyID), nil
	case VariantNoPrefix:
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid output prefix variant: %v", variant)
	}
}

func instanceFromMlDsaInstance(mlDSAInstance mldsa.Instance) (MLDSAInstance, error) {
	switch mlDSAInstance {
	case mldsa.MLDSA65:
		return MLDSA65, nil
	case mldsa.MLDSA87:
		return MLDSA87, nil
	default:
		return UnknownInstance, fmt.Errorf("unsupported ML-DSA instance: %v", mlDSAInstance)
	}
}

func variantFromMlDsaVariant(mlDSAVariant mldsa.Variant) (Variant, error) {
	switch mlDSAVariant {
	case mldsa.VariantTink:
		return VariantTink, nil
	case mldsa.VariantNoPrefix:
		return VariantNoPrefix, nil
	default:
		return VariantUnknown, fmt.Errorf("unsupported ML-DSA variant: %v", mlDSAVariant)
	}
}

// parametersForClassicalAlgorithm returns the parameters for the given classical algorithm.
func parametersForClassicalAlgorithm(classicalAlgorithm ClassicalAlgorithm) (key.Parameters, error) {
	switch classicalAlgorithm {
	case Ed25519:
		params, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
		if err != nil {
			return nil, err
		}
		return &params, nil
	case ECDSAP256:
		return ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix)
	case ECDSAP384:
		return ecdsa.NewParameters(ecdsa.NistP384, ecdsa.SHA384, ecdsa.DER, ecdsa.VariantNoPrefix)
	case ECDSAP521:
		return ecdsa.NewParameters(ecdsa.NistP521, ecdsa.SHA512, ecdsa.DER, ecdsa.VariantNoPrefix)
	case RSA3072PSS:
		return rsassapss.NewParameters(rsassapss.ParametersValues{
			ModulusSizeBits: 3072,
			SigHashType:     rsassapss.SHA256,
			MGF1HashType:    rsassapss.SHA256,
			PublicExponent:  f4,
			SaltLengthBytes: 32,
		}, rsassapss.VariantNoPrefix)
	case RSA4096PSS:
		return rsassapss.NewParameters(rsassapss.ParametersValues{
			ModulusSizeBits: 4096,
			SigHashType:     rsassapss.SHA384,
			MGF1HashType:    rsassapss.SHA384,
			PublicExponent:  f4,
			SaltLengthBytes: 48,
		}, rsassapss.VariantNoPrefix)
	case RSA3072PKCS1:
		return rsassapkcs1.NewParameters(3072, rsassapkcs1.SHA256, f4, rsassapkcs1.VariantNoPrefix)
	case RSA4096PKCS1:
		return rsassapkcs1.NewParameters(4096, rsassapkcs1.SHA384, f4, rsassapkcs1.VariantNoPrefix)
	default:
		return nil, fmt.Errorf("unsupported classical algorithm: %v", classicalAlgorithm)
	}
}

// parametersForMLDSA returns the parameters for the given ML-DSA instance.
func parametersForMLDSA(mlDSAInstance MLDSAInstance) (*mldsa.Parameters, error) {
	switch mlDSAInstance {
	case MLDSA65:
		return mldsa.NewParameters(mldsa.MLDSA65, mldsa.VariantNoPrefix)
	case MLDSA87:
		return mldsa.NewParameters(mldsa.MLDSA87, mldsa.VariantNoPrefix)
	default:
		return nil, fmt.Errorf("unsupported ML-DSA instance: %v", mlDSAInstance)
	}
}

// NewPublicKey creates a new composite ML-DSA public key.
// The provided classical public key needs to be of one of the following concrete types:
//
// - ed25519.PublicKey
// - ecdsa.PublicKey
// - rsassapss.PublicKey: in this case, modulus should be 3072 or 4096 bits and the public exponent must be 65537.
// - rsassapkcs1.PublicKey: in this case, modulus should be 3072 or 4096 bits and the public exponent must be 65537.
func NewPublicKey(mlDsaPublicKey *mldsa.PublicKey, classicalPublicKey key.Key, idRequirement uint32, parameters *Parameters) (*PublicKey, error) {
	expectedClassicalParams, err := parametersForClassicalAlgorithm(parameters.ClassicalAlgorithm())
	if err != nil {
		return nil, err
	}

	if !classicalPublicKey.Parameters().Equal(expectedClassicalParams) {
		return nil, fmt.Errorf("classical public key parameters do not match expected parameters")
	}

	expectedMlDsaparameters, err := parametersForMLDSA(parameters.MLDSAInstance())
	if err != nil {
		return nil, err
	}
	if !mlDsaPublicKey.Parameters().Equal(expectedMlDsaparameters) {
		return nil, fmt.Errorf("ML-DSA public key parameters do not match expected parameters")
	}

	outputPrefix, err := calculateOutputPrefix(parameters.Variant(), idRequirement)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		mlDSAPublicKey:     mlDsaPublicKey,
		classicalPublicKey: classicalPublicKey,
		params:             parameters,
		idRequirement:      idRequirement,
		outputPrefix:       outputPrefix,
	}, nil
}

// PrivateKey represents a composite ML-DSA private key.
type PrivateKey struct {
	publicKey           *PublicKey
	mlDsaPrivateKey     *mldsa.PrivateKey
	classicalPrivateKey key.Key
}

var _ key.Key = (*PrivateKey)(nil)

// MLDSAPrivateKey returns the ML-DSA private key.
func (k *PrivateKey) MLDSAPrivateKey() *mldsa.PrivateKey {
	return k.mlDsaPrivateKey
}

// ClassicalPrivateKey returns the classical private key.
func (k *PrivateKey) ClassicalPrivateKey() key.Key {
	return k.classicalPrivateKey
}

// PublicKey returns the public key of the key.
//
// This implements the privateKey interface defined in handle.go.
func (k *PrivateKey) PublicKey() (key.Key, error) { return k.publicKey, nil }

// Parameters returns the parameters of the key.
func (k *PrivateKey) Parameters() key.Parameters { return k.publicKey.params }

// IDRequirement returns the ID requirement of the key, and whether it is
// required.
func (k *PrivateKey) IDRequirement() (uint32, bool) { return k.publicKey.IDRequirement() }

// OutputPrefix returns the output prefix of this key.
func (k *PrivateKey) OutputPrefix() []byte { return bytes.Clone(k.publicKey.outputPrefix) }

// Equal returns true if this key is equal to other.
func (k *PrivateKey) Equal(other key.Key) bool {
	if k == other {
		return true
	}
	that, ok := other.(*PrivateKey)
	return ok && k.publicKey.Equal(that.publicKey) &&
		k.mlDsaPrivateKey.Equal(that.mlDsaPrivateKey) &&
		k.classicalPrivateKey.Equal(that.classicalPrivateKey)
}

// NewPrivateKey creates a new composite ML-DSA private key.
// The provided classical private key needs to be of one of the following concrete types:
//
// - ed25519.PrivateKey
// - ecdsa.PrivateKey
// - rsassapss.PrivateKey: in this case, modulus should be 3072 or 4096 bits.
// - rsassapkcs1.PrivateKey: in this case, modulus should be 4096 bits.
func NewPrivateKey(mlDsaPrivateKey *mldsa.PrivateKey, classicalPrivateKey key.Key, idRequirement uint32, parameters *Parameters) (*PrivateKey, error) {
	// The implementation of PublicKey() never fails in the case of ML-DSA, so we don't need to handle the error.
	mlDsaPublicKey, _ := mlDsaPrivateKey.PublicKey()

	classicalPrivPubKeyExposed, ok := classicalPrivateKey.(interface {
		PublicKey() (key.Key, error)
	})
	if !ok {
		return nil, fmt.Errorf("classicalPrivateKey of type %T does not expose a public key", classicalPrivateKey)
	}
	classicalPubKey, err := classicalPrivPubKeyExposed.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from classical private key: %v", err)
	}

	publicKey, err := NewPublicKey(mlDsaPublicKey.(*mldsa.PublicKey), classicalPubKey, idRequirement, parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to create composite public key: %v", err)
	}

	return &PrivateKey{
		publicKey:           publicKey,
		mlDsaPrivateKey:     mlDsaPrivateKey,
		classicalPrivateKey: classicalPrivateKey,
	}, nil
}

func createPrivateKey(p key.Parameters, idRequirement uint32) (key.Key, error) {
	params, ok := p.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: %T", p)
	}

	mlDsaParams, err := parametersForMLDSA(params.MLDSAInstance())
	if err != nil {
		return nil, fmt.Errorf("failed to get ML-DSA parameters: %v", err)
	}
	mlDsaPrivKey, err := keygenregistry.CreateKey(mlDsaParams, 0) // ML-DSA part has no ID requirement
	if err != nil {
		return nil, fmt.Errorf("failed to create ML-DSA private key: %v", err)
	}

	classicalParams, err := parametersForClassicalAlgorithm(params.ClassicalAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("failed to get classical parameters: %v", err)
	}
	classicalPrivKey, err := keygenregistry.CreateKey(classicalParams, 0) // Classical part has no ID requirement
	if err != nil {
		return nil, fmt.Errorf("failed to create classical private key: %v", err)
	}

	return NewPrivateKey(mlDsaPrivKey.(*mldsa.PrivateKey), classicalPrivKey, idRequirement, params)
}
