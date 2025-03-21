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

package hmac_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestHMACKeyetGenerationFromParams(t *testing.T) {
	opts := hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        hmac.VariantNoPrefix,
		HashType:       hmac.SHA256,
	}
	params, err := hmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("hmac.NewKeyParams(%v) err = %v, want nil", opts, err)
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

func TestHMACKeysetGenerationFromKey(t *testing.T) {
	opts := hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 20,
		Variant:        hmac.VariantTink,
		HashType:       hmac.SHA256,
	}
	params, err := hmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("hmac.NewKeyParams(%v) err = %v, want nil", opts, err)
	}
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/hmac_sha256_test.json#L37
	keyBytes := mustHexDecode(t, "85a7cbaae825bb82c9b6f6c5c2af5ac03d1f6daa63d2a93c189948ec41b9ded9")
	wantTag := slices.Concat([]byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04}, mustHexDecode(t, "0fe2f13bba2198f6dda1a084be928e304e9cb16a56bc0b7b939a073280244373")[:opts.TagSizeInBytes])
	data := mustHexDecode(t, "a59b")

	key, err := hmac.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), params, 0x01020304)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
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
