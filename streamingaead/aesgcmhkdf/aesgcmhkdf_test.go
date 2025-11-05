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

package aesgcmhkdf_test

import (
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestRegisterPrimitiveConstructor(t *testing.T) {
	aesGCMHKDFParams, err := aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{
		KeySizeInBytes:        32,
		DerivedKeySizeInBytes: 32,
		SegmentSizeInBytes:    1024,
		HKDFHashType:          aesgcmhkdf.SHA256,
	})
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewParameters() err = %v, want nil", err)
	}
	keyMaterialGCMHKDF := secretdata.NewBytesFromData([]byte("12345678901234567890123456789012"), insecuresecretdataaccess.Token{})
	aesGCMHKDFKey, err := aesgcmhkdf.NewKey(aesGCMHKDFParams, keyMaterialGCMHKDF)
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewKey() err = %v, want nil", err)
	}

	b := config.NewBuilder()
	configWithoutAESGCMHKDF := b.Build()

	// Should fail because aesgcmhkdf.RegisterPrimitiveConstructor() was not called.
	if _, err := configWithoutAESGCMHKDF.PrimitiveFromKey(aesGCMHKDFKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutAESGCMHKDF.PrimitiveFromKey() err = nil, want error")
	}

	// Register aesgcmhkdf.RegisterPrimitiveConstructor() and check that it now works.
	if err := aesgcmhkdf.RegisterPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("aesgcmhkdf.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithAESGCMHKDF := b.Build()
	p, err := configWithAESGCMHKDF.PrimitiveFromKey(aesGCMHKDFKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithAESGCMHKDF.PrimitiveFromKey() err = %v, want nil", err)
	}

	if _, ok := p.(tink.StreamingAEAD); !ok {
		t.Fatalf("p was of type %v, want tink.StreamingAEAD", reflect.TypeOf(p))
	}
}
