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

package jwt

import (
	"reflect"

	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt/jwthmac"
)

// RegisterJWTHMACPrimitiveConstructor registers the JWT MAC primitive constructor
// to the provided config.
// It is not part of Tink's public API.
func RegisterJWTHMACPrimitiveConstructor(c *config.Builder, t internalapi.Token) error {
	return c.RegisterPrimitiveConstructor(reflect.TypeFor[*jwthmac.Key](), createJWTHMAC, t)
}
