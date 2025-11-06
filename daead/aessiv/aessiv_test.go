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

package aessiv_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestRegisterPrimitiveConstructor(t *testing.T) {
	aesSIVParams, err := aessiv.NewParameters(64, aessiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	aesSIVKey, err := aessiv.NewKey(secretdata.NewBytesFromData(mustHexDecode(t, aesSIVKeyHex), testonlyinsecuresecretdataaccess.Token()), 0, aesSIVParams)
	if err != nil {
		t.Fatalf(" aessiv.NewKey() err = %v, want nil", err)
	}

	b := config.NewBuilder()
	configWithoutAESSIV := b.Build()

	// Should fail because aessiv.RegisterPrimitiveConstructor() was not called.
	if _, err := configWithoutAESSIV.PrimitiveFromKey(aesSIVKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutAESSIV.PrimitiveFromKey() err = nil, want error")
	}

	// Register aessiv.RegisterPrimitiveConstructor() and check that it now works.
	if err := aessiv.RegisterPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("aessiv.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithAESSIV := b.Build()
	p, err := configWithAESSIV.PrimitiveFromKey(aesSIVKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithAESSIV.PrimitiveFromKey() err = %v, want nil", err)
	}
	d, ok := p.(tink.DeterministicAEAD)
	if !ok {
		t.Fatalf("p was of type %v, want tink.DeterministicAEAD", reflect.TypeOf(p))
	}
	got, err := d.DecryptDeterministically(mustHexDecode(t, aesSIVCiphertextHex), mustHexDecode(t, aesSIVAad))
	if err != nil {
		t.Fatalf("d.DecryptDeterministically() err = %v, want nil", err)
	}
	if !bytes.Equal(got, mustHexDecode(t, aesSIVMsgHex)) {
		t.Errorf("d.DecryptDeterministically() = %v, want %v", got, mustHexDecode(t, aesSIVMsgHex))
	}

}
