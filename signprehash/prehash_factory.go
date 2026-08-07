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
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// NewPrehashWithConfig returns a [tink.Prehash] primitive from the given
// [keyset.Handle] and [keyset.Config].
func NewPrehashWithConfig(handle *keyset.Handle, config keyset.Config) (tink.Prehash, error) {
	if handle == nil {
		return nil, fmt.Errorf("signprehash.NewPrehashWithConfig: handle cannot be nil")
	}
	if handle.Len() == 0 {
		return nil, fmt.Errorf("signprehash.NewPrehashWithConfig: empty keyset handle")
	}
	primaryEntry, err := handle.Primary()
	if err != nil {
		return nil, fmt.Errorf("signprehash.NewPrehashWithConfig: failed to get primary entry: %v", err)
	}
	if primaryEntry.KeyStatus() != keyset.Enabled {
		return nil, fmt.Errorf("signprehash.NewPrehashWithConfig: primary entry is not enabled")
	}
	// Make sure this access doesn't get logged as key export.
	primaryEntry = primaryEntry.ToUnmonitoredEntry(internalapi.Token{})
	primary, _, err := factoryutil.PrimitiveFromKey[tink.Prehash](primaryEntry.Key(), config)
	if err != nil {
		return nil, fmt.Errorf("signprehash.NewPrehashWithConfig: failed to get primitive for primary key: %v", err)
	}
	logger, err := createPrehashLogger(handle)
	if err != nil {
		return nil, err
	}
	return &wrappedPrehash{
		prehash: primary,
		keyID:   primaryEntry.KeyID(),
		logger:  logger,
	}, nil
}

// NewPrehash returns a [tink.Prehash] primitive from the given keyset handle.
func NewPrehash(handle *keyset.Handle) (tink.Prehash, error) {
	cfg := signprehashconfig.V0()
	return NewPrehashWithConfig(handle, &cfg)
}

type wrappedPrehash struct {
	prehash tink.Prehash
	keyID   uint32
	logger  monitoring.Logger
}

var _ tink.Prehash = (*wrappedPrehash)(nil)

func (w *wrappedPrehash) ComputePrehash(data []byte) ([]byte, error) {
	prehash, err := w.prehash.ComputePrehash(data)
	if err != nil {
		w.logger.LogFailure()
		return nil, err
	}
	w.logger.Log(w.keyID, len(data))
	return prehash, nil
}

func createPrehashLogger(kh *keyset.Handle) (monitoring.Logger, error) {
	factory, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		return nil, err
	}
	return factory.CreateFor("prehash", "compute")
}
