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

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderivers"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	prfderpb "github.com/tink-crypto/tink-go/v2/proto/prf_based_deriver_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	prfBasedDeriverKeyVersion = 0
	prfBasedDeriverTypeURL    = "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"
)

var (
	errInvalidPRFBasedDeriverKeyFormat = errors.New("prf_based_deriver_key_manager: invalid key format")
)

type prfBasedDeriverKeyManager struct{}

var _ registry.KeyManager = (*prfBasedDeriverKeyManager)(nil)

func (km *prfBasedDeriverKeyManager) Primitive(serializedKey []byte) (any, error) {
	return nil, errors.New("prf_based_deriver_key_manager: not implemented; users should obtain an keyset.Handle and the primtive with keyderivation.New")
}

func (km *prfBasedDeriverKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidPRFBasedDeriverKeyFormat
	}
	keyFormat := &prfderpb.PrfBasedDeriverKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidPRFBasedDeriverKeyFormat
	}
	if keyFormat.GetParams() == nil {
		return nil, errors.New("prf_based_deriver_key_manager: nil PRF-Based Deriver params")
	}
	if err := validatePRFKeyTemplate(keyFormat.GetPrfKeyTemplate()); err != nil {
		return nil, fmt.Errorf("prf_based_deriver_key_manager: %v", err)
	}
	if err := validateDerivedKeyTemplate(keyFormat.GetParams().GetDerivedKeyTemplate()); err != nil {
		return nil, fmt.Errorf("prf_based_deriver_key_manager: %v", err)
	}
	prfKey, err := registry.NewKeyData(keyFormat.GetPrfKeyTemplate())
	if err != nil {
		return nil, errors.New("prf_based_deriver_key_manager: failed to generate key from PRF key template")
	}

	return &prfderpb.PrfBasedDeriverKey{
		Version: prfBasedDeriverKeyVersion,
		PrfKey:  prfKey,
		Params:  keyFormat.GetParams(),
	}, nil
}

func (km *prfBasedDeriverKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidPRFBasedDeriverKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         prfBasedDeriverTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

func (km *prfBasedDeriverKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == prfBasedDeriverTypeURL
}

func (km *prfBasedDeriverKeyManager) TypeURL() string {
	return prfBasedDeriverTypeURL
}

func validatePRFKeyTemplate(prfKeyTemplate *tinkpb.KeyTemplate) error {
	params, err := protoserialization.ParseParameters(prfKeyTemplate)
	if err != nil {
		return fmt.Errorf("failed to create parameters from key template: %v", err)
	}
	switch prfKeyTemplateType := params.(type) {
	case *aescmacprf.Parameters:
	case *hkdfprf.Parameters:
	case *hmacprf.Parameters:
		// Do nothing.
	default:
		return fmt.Errorf("invalid PRF key template type: %T", prfKeyTemplateType)
	}
	return nil
}

func validateDerivedKeyTemplate(derivedKeyTemplate *tinkpb.KeyTemplate) error {
	params, err := protoserialization.ParseParameters(derivedKeyTemplate)
	if err != nil {
		return fmt.Errorf("failed to create parameters from key template: %v", err)
	}
	if !keyderivers.CanDeriveKey(reflect.TypeOf(params)) {
		return fmt.Errorf("derived key template is not a derivable key type")
	}
	return nil
}
