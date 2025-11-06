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

package hkdfprf_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

func TestKeysetGenerationFromParams(t *testing.T) {
	params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, nil)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
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

func TestAddNewKeyFromParametersFailsWithInvalidKeySize(t *testing.T) {
	params, err := hkdfprf.NewParameters(16, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	km := keyset.NewManager()
	if _, err := km.AddNewKeyFromParameters(params); err == nil {
		t.Fatalf("km.AddNewKeyFromParameters() err = nil, want non-nil")
	}
}

func TestNewPRFSetFailsWithInvalidKeySize(t *testing.T) {
	params, err := hkdfprf.NewParameters(16, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	key, err := hkdfprf.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345"), testonlyinsecuresecretdataaccess.Token()), params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}
	km := keyset.NewManager()
	keyID, err := km.AddKey(key)
	if err != nil {
		t.Fatalf("km.AddKey() err = %v, want nil", err)
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

func TestNewPRFSetFailsWithInvalidHashFunction(t *testing.T) {
	params, err := hkdfprf.NewParameters(32, hkdfprf.SHA384, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	key, err := hkdfprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), testonlyinsecuresecretdataaccess.Token()), params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
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
	// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.2
	keyBytes := mustHexDecode(t, "000102030405060708090a0b0c0d0e0f"+
		"101112131415161718191a1b1c1d1e1f"+
		"202122232425262728292a2b2c2d2e2f"+
		"303132333435363738393a3b3c3d3e3f"+
		"404142434445464748494a4b4c4d4e4f")
	salt := mustHexDecode(t, "606162636465666768696a6b6c6d6e6f"+
		"707172737475767778797a7b7c7d7e7f"+
		"808182838485868788898a8b8c8d8e8f"+
		"909192939495969798999a9b9c9d9e9f"+
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	data := mustHexDecode(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"+
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"+
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"+
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"+
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	wantPRFOutput := mustHexDecode(t, "b11e398dc80327a1c8e7f78c596a4934"+
		"4f012eda2d4efad8a050cc4c19afa97c"+
		"59045a99cac7827271cb41c65e590e09"+
		"da3275600c2f09b8367793a9aca3db71"+
		"cc30c58179ec3e87c14c01d5c1f3434f"+
		"1d87")

	params, err := hkdfprf.NewParameters(len(keyBytes), hkdfprf.SHA256, salt)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	key, err := hkdfprf.NewKey(secretdata.NewBytesFromData(keyBytes, testonlyinsecuresecretdataaccess.Token()), params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
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
	gotPRFOutput, err := set.ComputePrimaryPRF(data, 32)
	if err != nil {
		t.Fatalf("set.ComputePrimaryPRF() err = %v, want nil", err)
	}
	if got, want := gotPRFOutput, wantPRFOutput[:32]; !bytes.Equal(got, want) {
		t.Errorf("gotPRFOutput = %x, want %x", got, want)
	}
}
