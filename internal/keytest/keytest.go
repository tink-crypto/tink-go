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

// Package keytest contains test-only key types and parameters.
package keytest

import (
	"fmt"
	"reflect"

	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
)

// RegisterPrimitiveConstructor accepts a config object and registers the
// keytest primitive constructor to the provided config.
func RegisterPrimitiveConstructor(b *config.Builder, t internalapi.Token) error {
	return b.RegisterPrimitiveConstructor(reflect.TypeFor[*Key](), primitiveConstructor, t)
}

func init() {
	if err := keygenregistry.RegisterKeyCreator[*Parameters](createKey); err != nil {
		panic(fmt.Sprintf("keytest.init() failed: %v", err))
	}
	if err := primitiveregistry.RegisterPrimitiveConstructor[*Key](primitiveConstructor); err != nil {
		panic(fmt.Sprintf("keytest.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeySerializer[*Key](&keySerializer{}); err != nil {
		panic(fmt.Sprintf("keytest.init() failed: %v", err))
	}
	if err := protoserialization.RegisterKeyParser(typeURL, &keyParser{}); err != nil {
		panic(fmt.Sprintf("keytest.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersSerializer[*Parameters](&parametersSerializer{}); err != nil {
		panic(fmt.Sprintf("keytest.init() failed: %v", err))
	}
	if err := protoserialization.RegisterParametersParser(typeURL, &parametersParser{}); err != nil {
		panic(fmt.Sprintf("keytest.init() failed: %v", err))
	}
}
