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

package aesctrhmac_test

import (
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestRegisterPrimitiveConstructor(t *testing.T) {
	aesCTRHMACParams, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        32,
		HkdfHashType:          aesctrhmac.SHA256,
		DerivedKeySizeInBytes: 32,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    16,
		SegmentSizeInBytes:    1024,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	keyMaterialCTRHMAC := secretdata.NewBytesFromData([]byte("12345678901234567890123456789012"), testonlyinsecuresecretdataaccess.Token())
	aesCTRHMACKey, err := aesctrhmac.NewKey(aesCTRHMACParams, keyMaterialCTRHMAC)
	if err != nil {
		t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
	}

	b := config.NewBuilder()
	configWithoutAESCTRHMAC := b.Build()

	// Should fail because aesctrhmac.RegisterPrimitiveConstructor() was not called.
	if _, err := configWithoutAESCTRHMAC.PrimitiveFromKey(aesCTRHMACKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutAESCTRHMAC.PrimitiveFromKey() err = nil, want error")
	}

	// Register aesctrhmac.RegisterPrimitiveConstructor() and check that it now works.
	if err := aesctrhmac.RegisterPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("aesctrhmac.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithAESCTRHMAC := b.Build()
	p, err := configWithAESCTRHMAC.PrimitiveFromKey(aesCTRHMACKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithAESCTRHMAC.PrimitiveFromKey() err = %v, want nil", err)
	}

	if _, ok := p.(tink.StreamingAEAD); !ok {
		t.Fatalf("p was of type %v, want tink.StreamingAEAD", reflect.TypeOf(p))
	}
}
