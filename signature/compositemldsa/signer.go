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
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	internal "github.com/tink-crypto/tink-go/v2/internal/signature/compositemldsa"
	internalmldsa "github.com/tink-crypto/tink-go/v2/internal/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	mldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type signer struct {
	prefix          []byte
	variant         Variant
	mldsaSecretKey  *internalmldsa.SecretKey
	classicalSigner tink.Signer
	label           []byte
}

var _ tink.Signer = (*signer)(nil)

func mldsaSecretKeyFromPrivateKey(privateKey *mldsa.PrivateKey) (*internalmldsa.SecretKey, error) {
	mldsaSeedBytes := privateKey.PrivateKeyBytes().Data(insecuresecretdataaccess.Token{})
	var seedBytes [internalmldsa.SecretKeySeedSize]byte
	copy(seedBytes[:], mldsaSeedBytes)

	params, ok := privateKey.Parameters().(*mldsa.Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid ML-DSA parameters type")
	}

	switch params.Instance() {
	case mldsa.MLDSA65:
		_, mldsaSecretKey := internalmldsa.MLDSA65.KeyGenFromSeed(seedBytes)
		return mldsaSecretKey, nil
	case mldsa.MLDSA87:
		_, mldsaSecretKey := internalmldsa.MLDSA87.KeyGenFromSeed(seedBytes)
		return mldsaSecretKey, nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA instance: %v", params.Instance())
	}
}

func newClassicalSigner(classicalPrivateKey key.Key) (tink.Signer, error) {
	switch k := classicalPrivateKey.(type) {
	case *ed25519.PrivateKey:
		return ed25519.NewSigner(k, internalapi.Token{})
	case *ecdsa.PrivateKey:
		return ecdsa.NewSigner(k, internalapi.Token{})
	case *rsassapss.PrivateKey:
		return rsassapss.NewSigner(k, internalapi.Token{})
	case *rsassapkcs1.PrivateKey:
		return rsassapkcs1.NewSigner(k, internalapi.Token{})
	default:
		return nil, fmt.Errorf("unsupported classical key type: %T", k)
	}
}

// NewSigner creates a new [tink.Signer] for ML-DSA.
//
// This is an internal API.
func NewSigner(privateKey *PrivateKey, _ internalapi.Token) (tink.Signer, error) {
	mldsaSecretKey, err := mldsaSecretKeyFromPrivateKey(privateKey.mlDsaPrivateKey)
	if err != nil {
		return nil, err
	}

	classicalSigner, err := newClassicalSigner(privateKey.classicalPrivateKey)
	if err != nil {
		return nil, err
	}

	params, ok := privateKey.Parameters().(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: %T", privateKey.Parameters())
	}
	internalInstance, err := toInternalMLDSAInstance(params.MLDSAInstance())
	if err != nil {
		return nil, err
	}
	internalAlg, err := toInternalClassicalAlgorithm(params.ClassicalAlgorithm())
	if err != nil {
		return nil, err
	}
	label, err := internal.ComputeLabel(internalInstance, internalAlg)
	if err != nil {
		return nil, err
	}

	return &signer{
		prefix:          privateKey.OutputPrefix(),
		variant:         params.Variant(),
		mldsaSecretKey:  mldsaSecretKey,
		classicalSigner: classicalSigner,
		label:           []byte(label),
	}, nil
}

// Sign computes a signature for the given data.
//
// If the key has a prefix, the signature will be prefixed with the output
// prefix.
func (e *signer) Sign(data []byte) ([]byte, error) {
	messagePrime := internal.ComputeMessagePrime(string(e.label), data)

	mldsaSign, err := e.mldsaSecretKey.Sign(messagePrime, e.label)
	if err != nil {
		return nil, err
	}
	classicalSign, err := e.classicalSigner.Sign(messagePrime)
	if err != nil {
		return nil, err
	}
	return slices.Concat(e.prefix, mldsaSign, classicalSign), nil
}

func signerConstructor(key key.Key) (any, error) {
	that, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not a %T", (*PrivateKey)(nil))
	}
	return NewSigner(that, internalapi.Token{})
}

func toInternalMLDSAInstance(instance MLDSAInstance) (internal.MLDSAInstance, error) {
	switch instance {
	case MLDSA65:
		return internal.MLDSA65, nil
	case MLDSA87:
		return internal.MLDSA87, nil
	default:
		return internal.UnknownInstance, fmt.Errorf("unsupported ML-DSA instance: %v", instance)
	}
}

func toInternalClassicalAlgorithm(alg ClassicalAlgorithm) (internal.ClassicalAlgorithm, error) {
	switch alg {
	case Ed25519:
		return internal.Ed25519, nil
	case ECDSAP256:
		return internal.ECDSAP256, nil
	case ECDSAP384:
		return internal.ECDSAP384, nil
	case ECDSAP521:
		return internal.ECDSAP521, nil
	case RSA3072PSS:
		return internal.RSA3072PSS, nil
	case RSA4096PSS:
		return internal.RSA4096PSS, nil
	case RSA3072PKCS1:
		return internal.RSA3072PKCS1, nil
	case RSA4096PKCS1:
		return internal.RSA4096PKCS1, nil
	default:
		return internal.UnknownAlgorithm, fmt.Errorf("unsupported classical algorithm: %v", alg)
	}
}
