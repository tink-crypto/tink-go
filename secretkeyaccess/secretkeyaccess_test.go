// Copyright 2024 Google LLC
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

package secretkeyaccess_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretkeyaccess"
	"github.com/tink-crypto/tink-go/v2/secretkeyaccess"
)

func TestValidateWithValidToken(t *testing.T) {
	if err := secretkeyaccess.Validate(insecuresecretkeyaccess.Token{}); err != nil {
		t.Errorf("secretkeyaccess.Validate(insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
}

func TestInvalidTokenReturnsError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token any
	}{
		{
			name:  "nil",
			token: nil,
		},
		{
			name:  "int",
			token: 42,
		},
		{
			name:  "string",
			token: "token",
		},
		{
			name:  "reference to insecuresecretkeyaccess.Token",
			token: &insecuresecretkeyaccess.Token{},
		},
	} {
		t.Run("Validate_"+tc.name, func(t *testing.T) {
			if err := secretkeyaccess.Validate(tc.token); err == nil {
				t.Errorf("secretkeyaccess.Validate(%v) = nil, want error", tc.token)
			}
		})

		data := []byte("secret key material")
		t.Run("NewBytesFromData_"+tc.name, func(t *testing.T) {
			if _, err := secretkeyaccess.NewBytesFromData(data, tc.token); err == nil {
				t.Errorf("secretkeyaccess.NewBytesFromData(%v, %v) = nil, want error", data, tc.token)
			}
		})

		t.Run("BytesData_"+tc.name, func(t *testing.T) {
			keyMaterial, err := secretkeyaccess.NewBytes(16)
			if err != nil {
				t.Fatalf("secretkeyaccess.NewBytes(16) = %v, want nil", err)
			}
			if _, err := keyMaterial.Data(tc.token); err == nil {
				t.Errorf("keyMaterial.Data(%v) = nil, want error", tc.token)
			}
		})
	}
}

func TestNewBytesLen(t *testing.T) {
	for _, size := range []uint32{0, 1, 16, 1024} {
		keyMaterial, err := secretkeyaccess.NewBytes(size)
		if err != nil {
			t.Fatalf("secretkeyaccess.NewBytes(%v) = %v, want nil", size, err)
		}
		if got, want := keyMaterial.Len(), int(size); got != want {
			t.Errorf("keyMaterial.Len() = %v, want %v", got, want)
		}
	}
}

func TestNewBytesFromDataLen(t *testing.T) {
	data := []byte("secret key material")
	keyMaterial, err := secretkeyaccess.NewBytesFromData(data, insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytesFromData(data, insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	if got, want := keyMaterial.Len(), len(data); got != want {
		t.Errorf("keyMaterial.Len() = %v, want %v", got, want)
	}
}

func TestBytesWithNilBytesHasZeroLen(t *testing.T) {
	keyMaterial, err := secretkeyaccess.NewBytesFromData(nil, insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytesFromData(nil, insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	if got, want := keyMaterial.Len(), 0; got != want {
		t.Errorf("keyMaterial.Len() = %v, want %v", got, want)
	}
}

func TestBytesBytesWithValidTokenReturnsData(t *testing.T) {
	expected := []byte("secret key material")
	keyMaterial, err := secretkeyaccess.NewBytesFromData(expected, insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytesFromData(expected, insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	got, err := keyMaterial.Data(insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("keyMaterial.Data(insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("bytes.Equal(got, expected) = false, want true")
	}
}

func TestBytesEquals(t *testing.T) {
	data := []byte("secret key material")
	keyMaterial, err := secretkeyaccess.NewBytesFromData(data, insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytesFromData(data, insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	otherBytes, err := secretkeyaccess.NewBytesFromData(data, insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytesFromData(data, insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	if !keyMaterial.Equals(otherBytes) {
		t.Errorf("keyMaterial.Equals(otherBytes) = false, want true")
	}

	differentBytes, err := secretkeyaccess.NewBytesFromData([]byte("different secret key material"), insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytesFromData(data, insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	if differentBytes.Equals(keyMaterial) {
		t.Errorf("differentBytes.Equals(keyMaterial) = true, want false")
	}
}

func TestBytesEqualsEmpty(t *testing.T) {
	nilSecretBytes, err := secretkeyaccess.NewBytesFromData(nil, insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytesFromData(nil, insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	emptySecretBytes, err := secretkeyaccess.NewBytesFromData([]byte(""), insecuresecretkeyaccess.Token{})
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytesFromData([]byte(\"\"), insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
	randomEmptyBytes, err := secretkeyaccess.NewBytes(0)
	if err != nil {
		t.Fatalf("secretkeyaccess.NewBytes(0) = %v, want nil", err)
	}
	testCases := []struct {
		name        string
		firstBytes  *secretkeyaccess.Bytes
		secondBytes *secretkeyaccess.Bytes
	}{
		{
			name:        "nil vs nil",
			firstBytes:  nilSecretBytes,
			secondBytes: nilSecretBytes,
		},
		{
			name:        "empty vs empty",
			firstBytes:  emptySecretBytes,
			secondBytes: emptySecretBytes,
		},
		{
			name:        "random empty vs random empty",
			firstBytes:  randomEmptyBytes,
			secondBytes: randomEmptyBytes,
		},
		{
			name:        "nil vs empty",
			firstBytes:  nilSecretBytes,
			secondBytes: emptySecretBytes,
		},
		{
			name:        "nil vs random empty",
			firstBytes:  nilSecretBytes,
			secondBytes: randomEmptyBytes,
		},
		{
			name:        "empty vs random empty",
			firstBytes:  emptySecretBytes,
			secondBytes: randomEmptyBytes,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if !testCase.firstBytes.Equals(testCase.secondBytes) {
				t.Errorf("firstBytes.Equals(secondBytes) = false, want true")
			}
		})
	}
}
