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

package slhdsa

import (
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// signer is an implementation of [tink.Signer] for SLH-DSA.
type signer struct {
	secretKey *slhdsa.SecretKey
	prefix    []byte
	variant   Variant
}

var _ tink.Signer = (*signer)(nil)

// These checks are gated by NewParameters filtering out invalid parameters.
func slhdsaSecretKeyFromPrivateKey(privateKey *PrivateKey) (*slhdsa.SecretKey, error) {
	switch privateKey.publicKey.params.paramSet {
	case slhDSASHA2128s():
		return slhdsa.SLH_DSA_SHA2_128s.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHAKE128s():
		return slhdsa.SLH_DSA_SHAKE_128s.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHA2128f():
		return slhdsa.SLH_DSA_SHA2_128f.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHAKE128f():
		return slhdsa.SLH_DSA_SHAKE_128f.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHA2192s():
		return slhdsa.SLH_DSA_SHA2_192s.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHAKE192s():
		return slhdsa.SLH_DSA_SHAKE_192s.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHA2192f():
		return slhdsa.SLH_DSA_SHA2_192f.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHAKE192f():
		return slhdsa.SLH_DSA_SHAKE_192f.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHA2256s():
		return slhdsa.SLH_DSA_SHA2_256s.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHAKE256s():
		return slhdsa.SLH_DSA_SHAKE_256s.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHA2256f():
		return slhdsa.SLH_DSA_SHA2_256f.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	case slhDSASHAKE256f():
		return slhdsa.SLH_DSA_SHAKE_256f.DecodeSecretKey(privateKey.keyBytes.Data(insecuresecretdataaccess.Token{}))
	default:
		return nil, fmt.Errorf("invalid parameters: %v", privateKey.publicKey.params)
	}
}

// NewSigner creates a new [tink.Signer] for SLH-DSA.
//
// This is an internal API.
func NewSigner(privateKey *PrivateKey, _ internalapi.Token) (tink.Signer, error) {
	secretKey, err := slhdsaSecretKeyFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &signer{
		secretKey: secretKey,
		prefix:    privateKey.OutputPrefix(),
		variant:   privateKey.publicKey.params.Variant(),
	}, nil
}

// Sign computes a signature for the given data.
//
// If the key has a prefix, the signature will be prefixed with the output
// prefix.
func (e *signer) Sign(data []byte) ([]byte, error) {
	r, err := e.secretKey.Sign(data, nil)
	if err != nil {
		return nil, err
	}
	return slices.Concat(e.prefix, r), nil
}

func signerConstructor(key key.Key) (any, error) {
	that, ok := key.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not a %T", (*PrivateKey)(nil))
	}
	return NewSigner(that, internalapi.Token{})
}
