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
	"encoding/binary"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/config/signprehashconfig"
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	// prehashStartByte is the first byte of every prehash value. This must agree
	// with the per-key implementations, for example signprehash/mldsa.
	prehashStartByte = 0xff
	// prehashPrefixSize is the size of the Tink framing that precedes the
	// algorithm specific payload: the start byte, followed by a 4 byte big endian
	// key ID.
	prehashPrefixSize = 5
)

// NewPrehashSignerWithConfig returns a [tink.PrehashSigner] primitive from the given
// [keyset.Handle] and [keyset.Config].
//
// The returned primitive signs a prehash value with the enabled key whose ID the
// prehash value names, which is not necessarily the primary key. Key selection
// here mirrors verification rather than signing: the prehashing side picks the
// key, and this side follows that choice. That is what makes a keyset rotatable,
// as a newly added key can sign as soon as it is enabled everywhere, and the old
// key keeps signing prehash values that are still in flight until it is disabled.
func NewPrehashSignerWithConfig(handle *keyset.Handle, config keyset.Config) (tink.PrehashSigner, error) {
	if handle == nil {
		return nil, fmt.Errorf("signprehash.NewPrehashSignerWithConfig: handle cannot be nil")
	}
	if handle.Len() == 0 {
		return nil, fmt.Errorf("signprehash.NewPrehashSignerWithConfig: empty keyset handle")
	}
	// Signing does not single out the primary key, but a keyset without a valid
	// primary is malformed.
	if _, err := handle.Primary(); err != nil {
		return nil, fmt.Errorf("signprehash.NewPrehashSignerWithConfig: failed to get primary entry: %v", err)
	}
	signers := make(map[uint32]tink.PrehashSigner)
	for entry := range factoryutil.EnabledUnmonitoredEntries(handle) {
		signer, _, err := factoryutil.PrimitiveFromKey[tink.PrehashSigner](entry.Key(), config)
		if err != nil {
			return nil, fmt.Errorf("signprehash.NewPrehashSignerWithConfig: failed to get primitive for key with ID %d: %v", entry.KeyID(), err)
		}
		signers[entry.KeyID()] = signer
	}
	logger, err := createPrehashSignerLogger(handle)
	if err != nil {
		return nil, err
	}
	return &wrappedPrehashSigner{
		signers: signers,
		logger:  logger,
	}, nil
}

// NewPrehashSigner returns a [tink.PrehashSigner] primitive from the given keyset handle.
func NewPrehashSigner(handle *keyset.Handle) (tink.PrehashSigner, error) {
	cfg := signprehashconfig.V0()
	return NewPrehashSignerWithConfig(handle, &cfg)
}

type wrappedPrehashSigner struct {
	signers map[uint32]tink.PrehashSigner
	logger  monitoring.Logger
}

var _ tink.PrehashSigner = (*wrappedPrehashSigner)(nil)

func (w *wrappedPrehashSigner) SignPrehash(prehash []byte) ([]byte, error) {
	if len(prehash) < prehashPrefixSize {
		w.logger.LogFailure()
		return nil, fmt.Errorf("signprehash.SignPrehash: prehash must be at least %d bytes, got %d", prehashPrefixSize, len(prehash))
	}
	if prehash[0] != prehashStartByte {
		w.logger.LogFailure()
		return nil, fmt.Errorf("signprehash.SignPrehash: prehash must start with %#x, got %#x", prehashStartByte, prehash[0])
	}
	keyID := binary.BigEndian.Uint32(prehash[1:prehashPrefixSize])
	signer, ok := w.signers[keyID]
	if !ok {
		w.logger.LogFailure()
		return nil, fmt.Errorf("signprehash.SignPrehash: keyset has no enabled key with key ID %d", keyID)
	}
	sig, err := signer.SignPrehash(prehash)
	if err != nil {
		w.logger.LogFailure()
		return nil, err
	}
	w.logger.Log(keyID, len(prehash))
	return sig, nil
}

func createPrehashSignerLogger(kh *keyset.Handle) (monitoring.Logger, error) {
	factory, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		return nil, err
	}
	return factory.CreateFor("prehash_signer", "sign")
}
