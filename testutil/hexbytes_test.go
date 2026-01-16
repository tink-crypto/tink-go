// Copyright 2019 Google LLC
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

package testutil_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/testutil"
)

func TestHexBytes(t *testing.T) {
	validHex := []byte("abc123")
	want, err := hex.DecodeString(string(validHex))
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", validHex, err)
	}

	var got testutil.HexBytes
	if err = got.UnmarshalText(validHex); err != nil {
		t.Fatalf("hb.UnmarshalText(%q) err = %v, want nil", validHex, err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("hb.UnmarshalText(%q); hb = %v, want %v", validHex, got, want)
	}
}

func TestHexBytes_DecodeError(t *testing.T) {
	invalidHex := []byte("xyz")
	var hb testutil.HexBytes
	err := hb.UnmarshalText(invalidHex)
	if err == nil {
		t.Errorf("hb.UnmarshalText(%q) = nil, want err", invalidHex)
	}
}
