// Copyright 2026 Google LLC
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
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestNewPRF(t *testing.T) {
	keyBytes := mustHexDecode(t, hmacSHA256KeyHex)
	params, err := hmacprf.NewParameters(len(keyBytes), hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	key, err := hmacprf.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), params)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}

	data := mustHexDecode(t, hmacSHA256DataHex)
	want := mustHexDecode(t, hmacSHA256WantOutputHex)

	p, err := hmacprf.NewPRF(key, internalapi.Token{})
	if err != nil {
		t.Fatalf("hmacprf.NewPRF(%T) err = %v, want nil", key, err)
	}
	got, err := p.ComputePRF(data, uint32(len(want)))
	if err != nil {
		t.Fatalf("p.ComputePRF(%x, %d) err = %v, want nil", data, len(want), err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("p.ComputePRF(%x, %d) = %x, want %x", data, len(want), got, want)
	}
}

func TestNewPRF_FailsWithInvalidKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  *hmacprf.Key
	}{
		{
			name: "nil_key",
			key:  nil,
		},
		{
			name: "empty_key",
			key:  &hmacprf.Key{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := hmacprf.NewPRF(tc.key, internalapi.Token{}); err == nil {
				t.Errorf("hmacprf.NewPRF(%T, internalapi.Token{}) err = nil, want error", tc.key)
			}
		})
	}
}
