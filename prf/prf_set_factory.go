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
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
)

// NewPRFSet creates a prf.Set primitive from the given keyset handle.
func NewPRFSet(handle *keyset.Handle) (*Set, error) {
	ps, err := keyset.Primitives[PRF](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("prf_set_factory: cannot obtain primitive set: %s", err)
	}
	return wrapPRFset(ps)
}

func wrapPRFset(ps *primitiveset.PrimitiveSet[PRF]) (*Set, error) {
	set := &Set{}
	set.PrimaryID = ps.Primary.KeyID
	set.PRFs = make(map[uint32]PRF)
	logger, err := createLogger(ps)
	if err != nil {
		return nil, err
	}
	entries, err := ps.RawEntries()
	if err != nil {
		return nil, fmt.Errorf("Could not get raw entries: %v", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("Did not find any raw entries")
	}
	if len(ps.Entries) != 1 {
		return nil, fmt.Errorf("Only raw entries allowed for prf.Set")
	}
	for _, entry := range entries {
		prf := entry.Primitive
		if prf == nil {
			prf = entry.FullPrimitive
		}
		set.PRFs[entry.KeyID] = &monitoredPRF{
			prf:    prf,
			keyID:  entry.KeyID,
			logger: logger,
		}
	}
	return set, nil
}

func createLogger(ps *primitiveset.PrimitiveSet[PRF]) (monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	return internalregistry.GetMonitoringClient().NewLogger(&monitoring.Context{
		KeysetInfo:  keysetInfo,
		Primitive:   "prf",
		APIFunction: "compute",
	})
}
