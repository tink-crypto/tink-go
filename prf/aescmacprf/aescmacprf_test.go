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

package aescmacprf_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestKeysetGenerationFromParams(t *testing.T) {
	params, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewKeyParams(%v) err = %v, want nil", 32, err)
	}
	km := keyset.NewManager()
	keyID, err := km.AddNewKeyFromParameters(&params)
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

func TestAddNewKeyFromParametersFailsWithInvalidKeySize(t *testing.T) {
	params, err := aescmacprf.NewParameters(16)
	if err != nil {
		t.Fatalf("aescmacprf.NewKeyParams(%v) err = %v, want nil", 16, err)
	}
	km := keyset.NewManager()
	if _, err := km.AddNewKeyFromParameters(&params); err == nil {
		t.Fatalf("km.AddNewKeyFromParameters() err = nil, want non-nil")
	}
}

func TestNewPRFSetFailsWithInvalidKeySize(t *testing.T) {
	key, err := aescmacprf.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
	}
	km := keyset.NewManager()
	keyID, err := km.AddKey(key)
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
	if _, err := prf.NewPRFSet(handle); err == nil {
		t.Fatalf("prf.NewPRFSet() err = nil, want non-nil")
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

func TestKeysetGenerationFromKey(t *testing.T) {
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1860
	keyBytes := mustHexDecode(t, "e754076ceab3fdaf4f9bcab7d4f0df0cbbafbc87731b8f9b7cd2166472e8eebc")
	wantPRFOutput := mustHexDecode(t, "9d47482c2d9252bace43a75a8335b8b8")
	data := mustHexDecode(t, "40")

	key, err := aescmacprf.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() err = %v, want nil", err)
	}

	params, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(%v) err = %v, want nil", 32, err)
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
	if _, err = km.AddNewKeyFromParameters(&params); err != nil {
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
	gotPRFOutput, err := set.ComputePrimaryPRF(data, 16)
	if err != nil {
		t.Fatalf("set.ComputePrimaryPRF() err = %v, want nil", err)
	}
	if got, want := gotPRFOutput, wantPRFOutput; !bytes.Equal(got, want) {
		t.Errorf("gotPRFOutput = %x, want %x", got, want)
	}
}
