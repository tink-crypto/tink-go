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

package hmacprf_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

func TestKeysetGenerationFromParams(t *testing.T) {
	params, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	km := keyset.NewManager()
	keyID, err := km.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("km.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	set, err := prf.NewPRFSet(handle)
	if err != nil {
		t.Fatalf("prf.NewPRFSet() err = %v, want nil", err)
	}
	data := []byte("data")
	if _, err := set.ComputePrimaryPRF(data, 16); err != nil {
		t.Fatalf("set.ComputePrimaryPRF() err = %v, want nil", err)
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex string %q: %v", s, err)
	}
	return b
}

const (
	// https://github.com/C2SP/wycheproof/blob/3bfb67fca7c7a2ef436e263da53cdabe0fa1dd36/testvectors/hmac_sha256_test.json#L31
	hmacSHA256KeyHex        = "8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a"
	hmacSHA256WantOutputHex = "dfc5105d5eecf7ae7b8b8de3930e7659e84c4172f2555142f1e568fc1872ad93"
	hmacSHA256DataHex       = "77"
)

func TestKeysetGenerationFromKey(t *testing.T) {
	// https://github.com/C2SP/wycheproof/blob/3bfb67fca7c7a2ef436e263da53cdabe0fa1dd36/testvectors/hmac_sha256_test.json#L31
	keyBytes := mustHexDecode(t, hmacSHA256KeyHex)
	data := mustHexDecode(t, hmacSHA256DataHex)
	wantPRFOutput := mustHexDecode(t, hmacSHA256WantOutputHex)

	params, err := hmacprf.NewParameters(len(keyBytes), hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	key, err := hmacprf.NewKey(secretdata.NewBytesFromData(keyBytes, testonlyinsecuresecretdataaccess.Token()), params)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddKey(key)
	if err != nil {
		t.Fatalf("km.AddKey() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	// Add non-primary key.
	if _, err = km.AddNewKeyFromParameters(params); err != nil {
		t.Fatalf("km.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	set, err := prf.NewPRFSet(handle)
	if err != nil {
		t.Fatalf("prf.NewPRFSet() err = %v, want nil", err)
	}
	gotPRFOutput, err := set.ComputePrimaryPRF(data, uint32(len(wantPRFOutput)))
	if err != nil {
		t.Fatalf("set.ComputePrimaryPRF() err = %v, want nil", err)
	}
	if got, want := gotPRFOutput, wantPRFOutput[:]; !bytes.Equal(got, want) {
		t.Errorf("gotPRFOutput = %x, want %x", got, want)
	}
}

func TestRegisterPrimitiveConstructor(t *testing.T) {
	hmacSHA256KeyBytes := mustHexDecode(t, hmacSHA256KeyHex)
	hmacSHA256PRFParams, err := hmacprf.NewParameters(len(hmacSHA256KeyBytes), hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256PRFKey, err := hmacprf.NewKey(secretdata.NewBytesFromData(hmacSHA256KeyBytes, testonlyinsecuresecretdataaccess.Token()), hmacSHA256PRFParams)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}

	b := config.NewBuilder()
	configWithoutHMACSHA256PRF := b.Build()

	// Should fail because hmacprf.RegisterPrimitiveConstructor() was not called.
	if _, err := configWithoutHMACSHA256PRF.PrimitiveFromKey(hmacSHA256PRFKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutHMACSHA256PRF.PrimitiveFromKey() err = nil, want error")
	}

	// Register hmacprf.RegisterPrimitiveConstructor() and check that it now works.
	if err := hmacprf.RegisterPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("hmacprf.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithHMACSHA256PRF := b.Build()
	primitive, err := configWithHMACSHA256PRF.PrimitiveFromKey(hmacSHA256PRFKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithHMACSHA256PRF.PrimitiveFromKey() err = %v, want nil", err)
	}
	p, ok := primitive.(prf.PRF)
	if !ok {
		t.Fatalf("p was of type %v, want prf.PRF", reflect.TypeOf(p))
	}
	want := mustHexDecode(t, hmacSHA256WantOutputHex)
	got, err := p.ComputePRF(mustHexDecode(t, hmacSHA256DataHex), uint32(len(want)))
	if err != nil {
		t.Fatalf("d.ComputePRF() err = %v, want nil", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("d.ComputePRF() = %x, want %x", got, want)
	}
}
