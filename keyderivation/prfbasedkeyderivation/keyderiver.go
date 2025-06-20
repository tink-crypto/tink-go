// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prfbasedkeyderivation

import (
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderiver"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/streamingprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type keyDeriver struct {
	key *Key

	derivedKeyTemplate *tinkpb.KeyTemplate
	streamingPRF       streamingprf.StreamingPRF
}

// NewKeyDeriver creates a new KeyDeriver.
//
// It constructs a [keyderiver.KeyDeriver] from the PRF key in the provided Key.
//
// This is an internal API.
func NewKeyDeriver(key *Key, _ internalapi.Token) (keyderiver.KeyDeriver, error) {
	if key == nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: key must not be nil")
	}
	prfKey := key.PRFKey()

	switch prfKey.(type) {
	case *hkdfprf.Key:
		// Do nothing.
	default:
		return nil, fmt.Errorf("unsupported PRF key type: %T", prfKey)
	}

	// Construct a StreamingPRF RAW primitive from the PRF key.
	prfKeyProtoSerialization, err := protoserialization.SerializeKey(prfKey)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: could not serialize prf key: %v", err)
	}
	hkdfStreamingPRFKeyManager := streamingprf.HKDFStreamingPRFKeyManager{}
	p, err := hkdfStreamingPRFKeyManager.Primitive(prfKeyProtoSerialization.KeyData().GetValue())
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: %v", err)
	}
	prf, ok := p.(streamingprf.StreamingPRF)
	if !ok {
		// This should never happen.
		return nil, errors.New("primitive is not StreamingPRF")
	}

	derivedKeyParameters := key.Parameters().(*Parameters).DerivedKeyParameters()
	derivedKeyTemplate, err := protoserialization.SerializeParameters(derivedKeyParameters)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: could not serialize derived key parameters: %v", err)
	}

	return &keyDeriver{
		key:                key,
		derivedKeyTemplate: derivedKeyTemplate,
		streamingPRF:       prf,
	}, nil
}

// DeriveKey derives a single key from the PRF-Based Deriver key.
//
// It produces a single key.Key.
func (k *keyDeriver) DeriveKey(salt []byte) (key.Key, error) {
	randomness, err := k.streamingPRF.Compute(salt)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: compute randomness from PRF failed: %v", err)
	}

	keyData, err := internalregistry.DeriveKey(k.derivedKeyTemplate, randomness)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: derive key failed: %v", err)
	}

	idRequirement, _ := k.key.IDRequirement()
	derivedKeySerialization, err := protoserialization.NewKeySerialization(keyData, k.derivedKeyTemplate.GetOutputPrefixType(), idRequirement)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: create derived key serialization failed: %v", err)
	}
	derivedKey, err := protoserialization.ParseKey(derivedKeySerialization)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: parsing the derived key failed: %v", err)
	}
	return derivedKey, nil
}

func primitiveConstructor(key key.Key) (any, error) {
	k, ok := key.(*Key)
	if !ok {
		return nil, fmt.Errorf("prfbasedkeyderivation: key is not a PRF-Based Deriver key")
	}
	return NewKeyDeriver(k, internalapi.Token{})
}
