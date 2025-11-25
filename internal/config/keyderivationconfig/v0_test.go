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

package keyderivationconfig

import (
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/prfbasedkeyderivation"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

type keyDeriver interface {
	// DeriveKey derives a new key.
	DeriveKey(salt []byte) (key.Key, error)
}

func TestRegisterPrimitiveConstructor(t *testing.T) {
	prfParams, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, nil)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	keyBytes := make([]byte, 32)
	prfKey, err := hkdfprf.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), prfParams)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	keyDerivationParams, err := prfbasedkeyderivation.NewParameters(prfParams, aes128GCMParams)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewParameters() err = %v, want nil", err)
	}
	keyDerivationKey, err := prfbasedkeyderivation.NewKey(keyDerivationParams, prfKey, 0x1234)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewKey() err = %v, want nil", err)
	}

	b := config.NewBuilder()
	configWithoutKeyDerivation := b.Build()

	// Should fail because prfbasedkeyderivation.RegisterPrimitiveConstructor() was not called.
	if _, err := configWithoutKeyDerivation.PrimitiveFromKey(keyDerivationKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutKeyDerivation.PrimitiveFromKey() err = nil, want error")
	}

	// Register prfbasedkeyderivation.RegisterPrimitiveConstructor() and check that it now works.
	if err := prfbasedkeyderivation.RegisterPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("prfbasedkeyderivation.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithKeyDerivation := b.Build()
	primitive, err := configWithKeyDerivation.PrimitiveFromKey(keyDerivationKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithKeyDerivation.PrimitiveFromKey() err = %v, want nil", err)
	}
	kd, ok := primitive.(keyDeriver)
	if !ok {
		t.Fatalf("primitive was of type %v, want keyDeriver", reflect.TypeOf(kd))
	}
	salt := []byte("salt")
	if _, err := kd.DeriveKey(salt); err != nil {
		t.Fatalf("kd.DeriveKey() err = %v, want nil", err)
	}
}
