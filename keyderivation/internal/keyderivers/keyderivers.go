// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package keyderivers provides functions to register and use key derivers.
package keyderivers

import (
	"fmt"
	"io"
	"reflect"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

var (
	keyDerivers = make(map[reflect.Type]keyDeriver)
)

type keyDeriver func(parameters key.Parameters, idRequirement uint32, reader io.Reader) (key.Key, error)

// DeriveKey derives a new [key.Key] from the given [key.Parameters].
//
// It looks up the appropriate key deriver from the registry based on the type
// of params.
func DeriveKey(params key.Parameters, idRequirement uint32, reader io.Reader) (key.Key, error) {
	pType := reflect.TypeOf(params)
	deriver, ok := keyDerivers[pType]
	if !ok {
		return nil, fmt.Errorf("no key deriver found for %v", pType)
	}
	return deriver(params, idRequirement, reader)
}

func addAESGCMKeyDeriver() {
	parametersType := reflect.TypeFor[*aesgcm.Parameters]()
	keyDerivers[parametersType] = func(p key.Parameters, idRequirement uint32, reader io.Reader) (key.Key, error) {
		aesGCMParams, ok := p.(*aesgcm.Parameters)
		if !ok {
			return nil, fmt.Errorf("key is of type %T; needed %T", p, &aesgcm.Parameters{})
		}
		keyBytes := make([]byte, aesGCMParams.KeySizeInBytes())
		if _, err := io.ReadFull(reader, keyBytes); err != nil {
			return nil, fmt.Errorf("not enough pseudorandomness given")
		}
		return aesgcm.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), idRequirement, aesGCMParams)
	}
}

func init() {
	// TODO: b/425280769 - Add key derivers for other key types.
	addAESGCMKeyDeriver()
}
