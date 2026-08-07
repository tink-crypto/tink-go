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

// NewPrehashSignerWithConfig returns a [tink.PrehashSigner] primitive from the given
// [keyset.Handle] and [keyset.Config].
func NewPrehashSignerWithConfig(handle *keyset.Handle, config keyset.Config) (tink.PrehashSigner, error) {
	if handle == nil {
		return nil, fmt.Errorf("signprehash.NewPrehashSignerWithConfig: handle cannot be nil")
	}
	if handle.Len() == 0 {
		return nil, fmt.Errorf("signprehash.NewPrehashSignerWithConfig: empty keyset handle")
	}
	primaryEntry, err := handle.Primary()
	if err != nil {
		return nil, fmt.Errorf("signprehash.NewPrehashSignerWithConfig: failed to get primary entry: %v", err)
	}
	// Make sure this access doesn't get logged as key export.
	primaryEntry = primaryEntry.ToUnmonitoredEntry(internalapi.Token{})
	primary, _, err := factoryutil.PrimitiveFromKey[tink.PrehashSigner](primaryEntry.Key(), config)
	if err != nil {
		return nil, fmt.Errorf("signprehash.NewPrehashSignerWithConfig: failed to get primitive for primary key: %v", err)
	}
	logger, err := createPrehashSignerLogger(handle)
	if err != nil {
		return nil, err
	}
	return &wrappedPrehashSigner{
		signer: primary,
		keyID:  primaryEntry.KeyID(),
		logger: logger,
	}, nil
}

// NewPrehashSigner returns a [tink.PrehashSigner] primitive from the given keyset handle.
func NewPrehashSigner(handle *keyset.Handle) (tink.PrehashSigner, error) {
	cfg := signprehashconfig.V0()
	return NewPrehashSignerWithConfig(handle, &cfg)
}

type wrappedPrehashSigner struct {
	signer tink.PrehashSigner
	keyID  uint32
	logger monitoring.Logger
}

var _ tink.PrehashSigner = (*wrappedPrehashSigner)(nil)

func (w *wrappedPrehashSigner) SignPrehash(prehash []byte) ([]byte, error) {
	sig, err := w.signer.SignPrehash(prehash)
	if err != nil {
		w.logger.LogFailure()
		return nil, err
	}
	w.logger.Log(w.keyID, len(prehash))
	return sig, nil
}

func createPrehashSignerLogger(kh *keyset.Handle) (monitoring.Logger, error) {
	factory, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		return nil, err
	}
	return factory.CreateFor("prehash_signer", "sign")
}
