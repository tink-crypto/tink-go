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

package prf

import (
	"fmt"
	"reflect"

	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf" // Also registers the AES-CMAC PRF key serialization.
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"       // Also registers the HKDF PRF key serialization.
)

func aesCMACPRFPrimitiveConstructor(key key.Key) (any, error) {
	actualKey, ok := key.(*aescmacprf.Key)
	if !ok {
		return nil, fmt.Errorf("invalid key type: got %T, want %T", key, (*aescmacprf.Key)(nil))
	}
	return aescmacprf.NewPRF(actualKey, internalapi.Token{})
}

func hkdfPRFPrimitiveConstructor(key key.Key) (any, error) {
	actualKey, ok := key.(*hkdfprf.Key)
	if !ok {
		return nil, fmt.Errorf("invalid key type: got %T, want %T", key, (*hkdfprf.Key)(nil))
	}
	return hkdfprf.NewPRF(actualKey, internalapi.Token{})
}

// RegisterAESCMACPRFPrimitiveConstructor registers the AES-CMAC PRF primitive constructor
// to the provided config.
//
// It is *NOT* part of the public API.
func RegisterAESCMACPRFPrimitiveConstructor(c *config.Builder, t internalapi.Token) error {
	return c.RegisterPrimitiveConstructor(reflect.TypeFor[*aescmacprf.Key](), aesCMACPRFPrimitiveConstructor, t)
}

// RegisterHKDFPRFPrimitiveConstructor registers the HKDF PRF primitive constructor
// to the provided config.
//
// It is *NOT* part of the public API.
func RegisterHKDFPRFPrimitiveConstructor(c *config.Builder, t internalapi.Token) error {
	return c.RegisterPrimitiveConstructor(reflect.TypeFor[*hkdfprf.Key](), hkdfPRFPrimitiveConstructor, t)
}

func init() {
	if err := primitiveregistry.RegisterPrimitiveConstructor[*aescmacprf.Key](aesCMACPRFPrimitiveConstructor); err != nil {
		panic(fmt.Sprintf("prf.init() failed: %v", err))
	}
	if err := primitiveregistry.RegisterPrimitiveConstructor[*hkdfprf.Key](hkdfPRFPrimitiveConstructor); err != nil {
		panic(fmt.Sprintf("prf.init() failed: %v", err))
	}
}
