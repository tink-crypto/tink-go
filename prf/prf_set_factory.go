// Copyright 2020 Google LLC
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
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
)

// NewPRFSet creates a [prf.Set] primitive from the given [keyset.Handle]
// using the global registry.
func NewPRFSet(handle *keyset.Handle) (*Set, error) {
	return NewPRFSetWithConfig(handle, &registryconfig.RegistryConfig{})
}

// NewPRFSetWithConfig creates a [prf.Set] primitive from the given [keyset.Handle] and
// [keyset.Config].
func NewPRFSetWithConfig(handle *keyset.Handle, config keyset.Config) (*Set, error) {
	logger, err := createLogger(handle)
	if err != nil {
		return nil, err
	}
	prfs := map[uint32]PRF{}
	primaryKeyID := uint32(0)
	for entry := range factoryutil.EnabledUnmonitoredEntries(handle) {
		primitive, _, err := factoryutil.PrimitiveFromKey[PRF](entry.Key(), config)
		if err != nil {
			return nil, err
		}
		if entry.IsPrimary() {
			primaryKeyID = entry.KeyID()
		}
		prfs[entry.KeyID()] = &monitoredPRF{
			prf:    primitive,
			keyID:  entry.KeyID(),
			logger: logger,
		}
	}
	return &Set{
		PrimaryID: primaryKeyID,
		PRFs:      prfs,
	}, nil
}

func createLogger(kh *keyset.Handle) (monitoring.Logger, error) {
	factory, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		return nil, err
	}
	return factory.CreateFor("prf", "compute")
}
