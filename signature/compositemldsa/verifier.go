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

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	internal "github.com/tink-crypto/tink-go/v2/internal/signature/compositemldsa"
	internalmldsa "github.com/tink-crypto/tink-go/v2/internal/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	mlDsa65SignatureLength = 3309
	mlDsa87SignatureLength = 4627
)

// verifier is an implementation of [tink.Verifier] for Composite ML-DSA.
type verifier struct {
	mlDsaPublicKey    *internalmldsa.PublicKey
	prefix            []byte
	classicalVerifier tink.Verifier
	label             []byte
	mlDSAInstance     MLDSAInstance
}

var _ tink.Verifier = (*verifier)(nil)

func mlDsaPublicKeyFromPublicKey(publicKey *PublicKey) (*internalmldsa.PublicKey, error) {
	mlDsaPubKeyBytes := publicKey.MLDSAPublicKey().KeyBytes()
	switch publicKey.Parameters().(*Parameters).MLDSAInstance() {
	case MLDSA65:
		return internalmldsa.MLDSA65.DecodePublicKey(mlDsaPubKeyBytes)
	case MLDSA87:
		return internalmldsa.MLDSA87.DecodePublicKey(mlDsaPubKeyBytes)
	default:
		return nil, fmt.Errorf("unsupported ML-DSA instance")
	}
}

func newClassicalVerifier(classicalPublicKey key.Key) (tink.Verifier, error) {
	switch k := classicalPublicKey.(type) {
	case *ed25519.PublicKey:
		return ed25519.NewVerifier(k, internalapi.Token{})
	case *ecdsa.PublicKey:
		return ecdsa.NewVerifier(k, internalapi.Token{})
	case *rsassapss.PublicKey:
		return rsassapss.NewVerifier(k, internalapi.Token{})
	case *rsassapkcs1.PublicKey:
		return rsassapkcs1.NewVerifier(k, internalapi.Token{})
	default:
		return nil, fmt.Errorf("unsupported classical key type: %T", k)
	}
}

// NewVerifier creates a new [tink.Verifier] for Composite ML-DSA.
//
// This is an internal API.
func NewVerifier(publicKey *PublicKey, _ internalapi.Token) (tink.Verifier, error) {
	mlDsaPubKey, err := mlDsaPublicKeyFromPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	classicalVerifier, err := newClassicalVerifier(publicKey.ClassicalPublicKey())
	if err != nil {
		return nil, err
	}
	params, ok := publicKey.Parameters().(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: %T", publicKey.Parameters())
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

	return &verifier{
		mlDsaPublicKey:    mlDsaPubKey,
		prefix:            publicKey.OutputPrefix(),
		classicalVerifier: classicalVerifier,
		label:             []byte(label),
		mlDSAInstance:     params.mlDSAInstance,
	}, nil

}

// Verify verifies whether the given signature is valid for the given data.
//
// It returns an error if the prefix is not valid or the signature is not
// valid.
func (v *verifier) Verify(signature, data []byte) error {
	if !bytes.HasPrefix(signature, v.prefix) {
		return fmt.Errorf("the signature does not have the expected prefix")
	}
	signature = signature[len(v.prefix):]

	var mlDsaSigLen int
	switch v.mlDSAInstance {
	case MLDSA65:
		mlDsaSigLen = mlDsa65SignatureLength
	case MLDSA87:
		mlDsaSigLen = mlDsa87SignatureLength
	default:
		return fmt.Errorf("invalid variant: %v", v.mlDSAInstance)
	}

	if len(signature) < mlDsaSigLen {
		return fmt.Errorf("signature length is shorter than ML-DSA signature length, expected at least %d, got %d", mlDsaSigLen, len(signature))
	}
	mlDsaSig := signature[:mlDsaSigLen]
	classicalSig := signature[mlDsaSigLen:]

	messagePrime := internal.ComputeMessagePrime(string(v.label), data)

	if err := v.mlDsaPublicKey.Verify(messagePrime, mlDsaSig, v.label); err != nil {
		return fmt.Errorf("ML-DSA verification failed: %v", err)
	}
	if err := v.classicalVerifier.Verify(classicalSig, messagePrime); err != nil {
		return fmt.Errorf("classical verification failed: %v", err)
	}
	return nil
}

func verifierConstructor(key key.Key) (any, error) {
	publicKey, ok := key.(*PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not a %T", (*PublicKey)(nil))
	}
	return NewVerifier(publicKey, internalapi.Token{})
}
