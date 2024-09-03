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
	"fmt"
	"log"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

type Key struct {
	keyMaterial secretdata.Bytes
}

func NewKey() (*Key, error) {
	keyMaterial, err := secretdata.NewBytesFromRand(32)
	if err != nil {
		return nil, err
	}
	return &Key{keyMaterial: keyMaterial}, nil
}

func (k *Key) Key() secretdata.Bytes { return k.keyMaterial }

func ExampleBytes() {
	key, err := NewKey()
	if err != nil {
		log.Fatal(err)
	}

	// APIs can safely return the the key material wrapped in a secretdata.Bytes
	// value.
	keyMaterial := key.Key()
	if err != nil {
		log.Fatal(err)
	}

	// Extracting the wrapped data requires an insecuresecretdataaccess.Token
	// value.
	keyMaterialData := keyMaterial.Data(insecuresecretdataaccess.Token{})
	fmt.Println(len(keyMaterialData))
	// Output: 32
}
