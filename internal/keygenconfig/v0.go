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

package keygenconfig

import (
	"fmt"
	"reflect"

	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcmsiv"
	"github.com/tink-crypto/tink-go/v2/aead/chacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/aead/xaesgcm"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
)

var configV0 = mustCreateConfigV0()

func mustCreateConfigV0() Config {
	config := New()

	if err := config.RegisterKeyCreator(reflect.TypeFor[*aesgcm.Parameters](), aesgcm.KeyCreator(internalapi.Token{})); err != nil {
		panic(fmt.Sprintf("keygenconfig: failed to register AES-GCM: %v", err))
	}
	if err := config.RegisterKeyCreator(reflect.TypeFor[*aesctrhmac.Parameters](), aesctrhmac.KeyCreator(internalapi.Token{})); err != nil {
		panic(fmt.Sprintf("keygenconfig: failed to register AES-CTR-HMAC: %v", err))
	}
	if err := config.RegisterKeyCreator(reflect.TypeFor[*aesgcmsiv.Parameters](), aesgcmsiv.KeyCreator(internalapi.Token{})); err != nil {
		panic(fmt.Sprintf("keygenconfig: failed to register AES-GCM-SIV: %v", err))
	}
	if err := config.RegisterKeyCreator(reflect.TypeFor[*chacha20poly1305.Parameters](), chacha20poly1305.KeyCreator(internalapi.Token{})); err != nil {
		panic(fmt.Sprintf("keygenconfig: failed to register ChaCha20-Poly1305: %v", err))
	}
	if err := config.RegisterKeyCreator(reflect.TypeFor[*xaesgcm.Parameters](), xaesgcm.KeyCreator(internalapi.Token{})); err != nil {
		panic(fmt.Sprintf("keygenconfig: failed to register XAES-GCM: %v", err))
	}

	return *config
}

// V0 returns an instance of the ConfigV0.
func V0() Config {
	return configV0
}
