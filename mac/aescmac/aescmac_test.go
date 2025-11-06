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

package aescmac_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/aescmac"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

func TestAESCMACKeyetGenerationFromParams(t *testing.T) {
	opts := aescmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aescmac.VariantNoPrefix,
	}
	params, err := aescmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("aescmac.NewKeyParams(%v) err = %v, want nil", opts, err)
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

	m, err := mac.New(handle)
	if err != nil {
		t.Fatalf("mac.New() err = %v, want nil", err)
	}
	data := []byte("data")
	tag, err := m.ComputeMAC(data)
	if err != nil {
		t.Fatalf("m.ComputeMAC() err = %v, want nil", err)
	}
	if got, want := len(tag), opts.TagSizeInBytes; got != want {
		t.Errorf("len(tag) = %d, want %d", got, want)
	}
}

func TestAESCMACKeysetGenerationFromKey(t *testing.T) {
	opts := aescmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aescmac.VariantTink,
	}
	params, err := aescmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("aescmac.NewKeyParams(%v) err = %v, want nil", opts, err)
	}
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1860
	keyBytes := mustHexDecode(t, "e754076ceab3fdaf4f9bcab7d4f0df0cbbafbc87731b8f9b7cd2166472e8eebc")
	wantTag := slices.Concat([]byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04}, mustHexDecode(t, "9d47482c2d9252bace43a75a8335b8b8"))
	data := mustHexDecode(t, "40")

	key, err := aescmac.NewKey(secretdata.NewBytesFromData(keyBytes, testonlyinsecuresecretdataaccess.Token()), params, 0x01020304)
	if err != nil {
		t.Fatalf("aescmac.NewKey() err = %v, want nil", err)
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
	m, err := mac.New(handle)
	if err != nil {
		t.Fatalf("mac.New() err = %v, want nil", err)
	}
	tag, err := m.ComputeMAC(data)
	if err != nil {
		t.Fatalf("m.ComputeMAC() err = %v, want nil", err)
	}
	if got, want := tag, wantTag; !bytes.Equal(got, want) {
		t.Errorf("tag = %x, want %x", got, want)
	}
}
