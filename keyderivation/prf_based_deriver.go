// Copyright 2022 Google LLC
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

package keyderivation

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderiver"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderivers"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/streamingprf"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const hkdfPRFTypeURL = "type.googleapis.com/google.crypto.tink.HkdfPrfKey"

// prfBasedDeriver uses prf and the Tink registry to derive a keyset handle as
// described by derivedKeyTemplate.
type prfBasedDeriver struct {
	prf              streamingprf.StreamingPRF
	derivedKeyParams key.Parameters
}

var _ KeysetDeriver = (*prfBasedDeriver)(nil)
var _ keyderiver.KeyDeriver = (*prfBasedDeriver)(nil)

func newPRFBasedDeriver(prfKeyData *tinkpb.KeyData, derivedKeyTemplate *tinkpb.KeyTemplate) (*prfBasedDeriver, error) {
	// Obtain Streaming PRF from PRF key data.
	if prfKeyData == nil {
		return nil, errors.New("PRF key data is nil")
	}
	if prfKeyData.GetTypeUrl() != hkdfPRFTypeURL {
		return nil, fmt.Errorf("PRF key data with type URL %q is not supported", prfKeyData.GetTypeUrl())
	}
	// For HKDF PRF keys, create a local instance of the HKDF Streaming PRF key
	// manager and obtain the Streaming PRF interface through it, instead of
	// obtaining it through the registry. This allows us to keep the HKDF
	// Streaming PRF key manager out of the registry for smoother deprecation.
	//
	// TODO(b/260619626): Remove this once PRF and Streaming PRF share the same
	// type URL and registry.Primitive() can return multiple interfaces per
	// primitive.
	hkdfStreamingPRFKeyManager := streamingprf.HKDFStreamingPRFKeyManager{}
	p, err := hkdfStreamingPRFKeyManager.Primitive(prfKeyData.GetValue())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve StreamingPRF primitive from key manager: %v", err)
	}
	prf, ok := p.(streamingprf.StreamingPRF)
	if !ok {
		return nil, errors.New("primitive is not StreamingPRF")
	}
	params, err := protoserialization.ParseParameters(derivedKeyTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters from key template: %v", err)
	}
	// Validate derived key template.
	if !keyderivers.CanDeriveKey(reflect.TypeOf(params)) {
		return nil, errors.New("derived key template is not a derivable key type")
	}
	return &prfBasedDeriver{
		prf:              prf,
		derivedKeyParams: params,
	}, nil
}

func (p *prfBasedDeriver) DeriveKey(salt []byte) (key.Key, error) {
	randomness, err := p.prf.Compute(salt)
	if err != nil {
		return nil, fmt.Errorf("compute randomness from PRF failed: %v", err)
	}
	key, err := keyderivers.DeriveKey(p.derivedKeyParams, 0, randomness, insecuresecretdataaccess.Token{})
	if err != nil {
		return nil, fmt.Errorf("derive key failed: %v", err)
	}

	// We can rely on protoserialization to have the correct key parser already
	// registered for two reasons:
	//  1. While Tink users can register key managers, there is no public API
	//     to add key derivers.
	//  2. When imported, keyderivers will register all protoserialization
	//     parsers/serializers.
	keySerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		return nil, fmt.Errorf("create key serialization failed: %v", err)
	}
	// Replace output prefix with RAW.
	newKeySerialization, err := protoserialization.NewKeySerialization(keySerialization.KeyData(), tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("create key serialization failed: %v", err)
	}
	return protoserialization.ParseKey(newKeySerialization)
}

// DeriveKeyset is a legacy implementation of the [KeysetDeriver] interface.
//
// This is deprecated, use DeriveKey instead.
func (p *prfBasedDeriver) DeriveKeyset(salt []byte) (*keyset.Handle, error) {
	key, err := p.DeriveKey(salt)
	if err != nil {
		return nil, fmt.Errorf("derive key failed: %v", err)
	}
	km := keyset.NewManager()
	keyID, err := km.AddKeyWithOpts(key, internalapi.Token{}, keyset.WithFixedID(0))
	if err != nil {
		return nil, fmt.Errorf("add key failed: %v", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		return nil, fmt.Errorf("set primary key failed: %v", err)
	}
	return km.Handle()
}
