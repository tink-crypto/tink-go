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

package aescmacprf

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/prf/subtle"
)

// NewPRF creates a new [subtle.AESCMACPRF] from the given [Key].
//
// This is an internal API.
func NewPRF(key *Key, _ internalapi.Token) (*subtle.AESCMACPRF, error) {
	if key == nil {
		return nil, fmt.Errorf("aescmacprf.NewPRF: key must not be nil")
	}
	if err := subtle.ValidateAESCMACPRFParams(uint32(key.KeyBytes().Len())); err != nil {
		return nil, err
	}
	return subtle.NewAESCMACPRF(key.KeyBytes().Data(insecuresecretdataaccess.Token{}))
}
