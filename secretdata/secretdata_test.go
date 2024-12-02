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

package secretdata_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestBytesWithStructLiteralAndBuiltInNewHaveZeroLen(t *testing.T) {
	bytes := secretdata.Bytes{}
	if got, want := bytes.Len(), 0; got != want {
		t.Errorf("bytes.Len() = %v, want %v", got, want)
	}
	bytesWithNew := new(secretdata.Bytes)
	if got, want := bytesWithNew.Len(), 0; got != want {
		t.Errorf("bytesWithNew.Len() = %v, want %v", got, want)
	}
}

func TestNewBytesLen(t *testing.T) {
	for _, size := range []uint32{0, 1, 16, 1024} {
		keyMaterial, err := secretdata.NewBytesFromRand(size)
		if err != nil {
			t.Fatalf("secretdata.NewBytesFromRand(%v) = %v, want nil", size, err)
		}
		if got, want := keyMaterial.Len(), int(size); got != want {
			t.Errorf("keyMaterial.Len() = %v, want %v", got, want)
		}
	}
}

func TestNewBytesFromDataLen(t *testing.T) {
	data := []byte("secret key material")
	keyMaterial := secretdata.NewBytesFromData(data, insecuresecretdataaccess.Token{})
	if got, want := keyMaterial.Len(), len(data); got != want {
		t.Errorf("keyMaterial.Len() = %v, want %v", got, want)
	}
}

func TestBytesWithNilBytesHasZeroLen(t *testing.T) {
	keyMaterial := secretdata.NewBytesFromData(nil, insecuresecretdataaccess.Token{})
	if got, want := keyMaterial.Len(), 0; got != want {
		t.Errorf("keyMaterial.Len() = %v, want %v", got, want)
	}
}

func TestBytesData(t *testing.T) {
	expected := []byte("secret key material")
	keyMaterial := secretdata.NewBytesFromData(expected, insecuresecretdataaccess.Token{})
	got := keyMaterial.Data(insecuresecretdataaccess.Token{})
	if !bytes.Equal(got, expected) {
		t.Errorf("bytes.Equal(got, expected) = false, want true")
	}
}

func TestBytesEqual(t *testing.T) {
	data := []byte("secret key material")
	keyMaterial := secretdata.NewBytesFromData(data, insecuresecretdataaccess.Token{})
	otherBytes := secretdata.NewBytesFromData(data, insecuresecretdataaccess.Token{})
	if !keyMaterial.Equal(otherBytes) {
		t.Errorf("keyMaterial.Equal(otherBytes) = false, want true")
	}
	differentBytes := secretdata.NewBytesFromData([]byte("different secret key material"), insecuresecretdataaccess.Token{})
	if differentBytes.Equal(keyMaterial) {
		t.Errorf("differentBytes.Equal(keyMaterial) = true, want false")
	}
}

func TestBytesEqualEmpty(t *testing.T) {
	nilBytes := secretdata.NewBytesFromData(nil, insecuresecretdataaccess.Token{})
	emptyBytes := secretdata.NewBytesFromData([]byte(""), insecuresecretdataaccess.Token{})
	randomEmptyBytes, err := secretdata.NewBytesFromRand(0)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(0) = %v, want nil", err)
	}
	structLiteralBytes := secretdata.Bytes{}
	testCases := []struct {
		name        string
		firstBytes  secretdata.Bytes
		secondBytes secretdata.Bytes
	}{
		{
			name:        "nil vs nil",
			firstBytes:  nilBytes,
			secondBytes: nilBytes,
		},
		{
			name:        "empty vs empty",
			firstBytes:  emptyBytes,
			secondBytes: emptyBytes,
		},
		{
			name:        "random empty vs random empty",
			firstBytes:  randomEmptyBytes,
			secondBytes: randomEmptyBytes,
		},
		{
			name:        "struct literal vs struct literal",
			firstBytes:  structLiteralBytes,
			secondBytes: structLiteralBytes,
		},
		{
			name:        "nil vs empty",
			firstBytes:  nilBytes,
			secondBytes: emptyBytes,
		},
		{
			name:        "nil vs random empty",
			firstBytes:  nilBytes,
			secondBytes: randomEmptyBytes,
		},
		{
			name:        "nil vs struct literal",
			firstBytes:  nilBytes,
			secondBytes: structLiteralBytes,
		},
		{
			name:        "empty vs random empty",
			firstBytes:  emptyBytes,
			secondBytes: randomEmptyBytes,
		},
		{
			name:        "empty vs struct literal",
			firstBytes:  emptyBytes,
			secondBytes: structLiteralBytes,
		},
		{
			name:        "random empty vs struct literal",
			firstBytes:  randomEmptyBytes,
			secondBytes: structLiteralBytes,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if !testCase.firstBytes.Equal(testCase.secondBytes) {
				t.Errorf("firstBytes.Equal(secondBytes) = false, want true")
			}
		})
	}
}
