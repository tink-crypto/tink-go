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

// Package aescmacprf provides a key manager for AES-CMAC PRF.
package aescmacprf

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/registry"
)

func init() {
	if err := registry.RegisterKeyManager(new(keyManager)); err != nil {
		panic(fmt.Sprintf("aescmacprf.init() failed: %v", err))
	}
}
