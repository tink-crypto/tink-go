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

package signprehash

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/config/signprehashconfig"
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// NewPrehash returns a [tink.Prehash] primitive from the given keyset handle.
func NewPrehash(handle *keyset.Handle) (tink.Prehash, error) {
	if handle == nil {
		return nil, fmt.Errorf("signprehash.NewPrehash: handle cannot be nil")
	}
	cfg := signprehashconfig.V0()
	primaryEntry, err := handle.Primary()
	if err != nil {
		return nil, fmt.Errorf("signprehash.NewPrehash: failed to get primary entry: %v", err)
	}
	if primaryEntry.KeyStatus() != keyset.Enabled {
		return nil, fmt.Errorf("signprehash.NewPrehash: primary entry is not enabled")
	}
	primary, _, err := factoryutil.PrimitiveFromKey[tink.Prehash](primaryEntry.Key(), &cfg)
	if err != nil {
		return nil, fmt.Errorf("signprehash.NewPrehash: failed to get primitive for primary key: %v", err)
	}
	return primary, nil
}
