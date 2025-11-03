// Copyright 2019 Google LLC
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

package hybrid

import (
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// NewHybridEncrypt returns an HybridEncrypt primitive from the given keyset handle.
func NewHybridEncrypt(handle *keyset.Handle) (tink.HybridEncrypt, error) {
	ps, err := keyset.Primitives[tink.HybridEncrypt](handle, &registryconfig.RegistryConfig{}, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("hybrid_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedHybridEncrypt(ps)
}

// fullHybridEncryptAdapter is an [tink.HybridEncrypt] implementation that
// makes a given RAW [tink.HybridEncrypt] a full primitive prepending the
// prefix the resulting ciphertext.
type fullHybridEncryptAdapter struct {
	rawHybridEncrypt tink.HybridEncrypt
	prefix           []byte
}

var _ tink.HybridEncrypt = (*fullHybridEncryptAdapter)(nil)

func (e *fullHybridEncryptAdapter) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	ct, err := e.rawHybridEncrypt.Encrypt(plaintext, contextInfo)
	if err != nil {
		return nil, err
	}
	return slices.Concat(e.prefix, ct), nil
}

// encryptPrimitiveSet is an HybridEncrypt implementation that uses the underlying primitive set for encryption.
type wrappedHybridEncrypt struct {
	fullPrimitive tink.HybridEncrypt
	logger        monitoring.Logger
	keyID         uint32
}

// compile time assertion that wrappedHybridEncrypt implements the HybridEncrypt interface.
var _ tink.HybridEncrypt = (*wrappedHybridEncrypt)(nil)

// Encrypt encrypts the given plaintext binding contextInfo to the resulting ciphertext.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *wrappedHybridEncrypt) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	ct, err := a.fullPrimitive.Encrypt(plaintext, contextInfo)
	if err != nil {
		a.logger.LogFailure()
		return nil, err
	}
	a.logger.Log(a.keyID, len(plaintext))
	return ct, nil
}

func isAEAD(p any) bool {
	if p == nil {
		return false
	}
	_, ok := p.(tink.AEAD)
	return ok
}

func newWrappedHybridEncrypt(ps *primitiveset.PrimitiveSet[tink.HybridEncrypt]) (*wrappedHybridEncrypt, error) {
	// Make sure the primitives do not implement tink.AEAD.
	if isAEAD(ps.Primary.Primitive) || isAEAD(ps.Primary.FullPrimitive) {
		return nil, fmt.Errorf("hybrid_factory: primary primitive must NOT implement tink.AEAD")
	}
	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if isAEAD(p.Primitive) || isAEAD(p.FullPrimitive) {
				return nil, fmt.Errorf("hybrid_factory: primitive must NOT implement tink.AEAD")
			}
		}
	}

	primitive := ps.Primary.FullPrimitive
	if primitive == nil {
		primitive = &fullHybridEncryptAdapter{
			rawHybridEncrypt: ps.Primary.Primitive,
			prefix:           ps.Primary.OutputPrefix(),
		}
	}

	logger, err := createEncryptLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedHybridEncrypt{
		fullPrimitive: primitive,
		logger:        logger,
		keyID:         ps.Primary.KeyID,
	}, nil
}

func createEncryptLogger(ps *primitiveset.PrimitiveSet[tink.HybridEncrypt]) (monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	return internalregistry.GetMonitoringClient().NewLogger(&monitoring.Context{
		KeysetInfo:  keysetInfo,
		Primitive:   "hybrid_encrypt",
		APIFunction: "encrypt",
	})
}
