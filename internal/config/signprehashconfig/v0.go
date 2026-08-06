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

// Package signprehashconfig provides registry configuration for signprehash primitives.
package signprehashconfig

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	mldsa "github.com/tink-crypto/tink-go/v2/signprehash/mldsa"
)

var configV0 = mustCreateConfigV0()

func mustCreateConfigV0() config.Config {
	builder := config.NewBuilder()
	if err := mldsa.RegisterPrimitiveConstructor(builder, internalapi.Token{}); err != nil {
		panic(fmt.Sprintf("mustCreateConfigV0() failed: %v", err))
	}
	return builder.Build()
}

// V0 returns a config that includes primitive constructors for signprehash primitives.
func V0() config.Config { return configV0 }
