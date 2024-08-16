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
	"fmt"
	"log"

	"github.com/tink-crypto/tink-go/v2/insecuresecretkeyaccess"
	"github.com/tink-crypto/tink-go/v2/secretkeyaccess"
)

type Key struct {
	key *secretkeyaccess.Bytes
}

func NewKey() (*Key, error) {
	key, err := secretkeyaccess.NewBytes(32)
	if err != nil {
		return nil, err
	}
	return &Key{key: key}, nil
}

func (k *Key) Key() *secretkeyaccess.Bytes { return k.key }

func ExampleBytes() {
	key, err := NewKey()
	if err != nil {
		log.Fatal(err)
	}

	// APIs can safely return the the key material wrapped in a
	// secretkeyaccess.Bytes object.
	keyMaterial := key.Key()
	if err != nil {
		log.Fatal(err)
	}

	// Extracting the wrapped key material requires an
	// insecuresecretkeyaccess.Token object.
	keyMaterialBytes, err := keyMaterial.Data(insecuresecretkeyaccess.Token{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(keyMaterialBytes))
	// Output: 32
}
