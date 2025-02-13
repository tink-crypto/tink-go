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

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// NewHybridEncrypt returns an HybridEncrypt primitive from the given keyset handle.
func NewHybridEncrypt(handle *keyset.Handle) (tink.HybridEncrypt, error) {
	ps, err := keyset.Primitives[tink.HybridEncrypt](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("hybrid_factory: cannot obtain primitive set: %s", err)
	}
	return newEncryptPrimitiveSet(ps)
}

// encryptPrimitiveSet is an HybridEncrypt implementation that uses the underlying primitive set for encryption.
type wrappedHybridEncrypt struct {
	ps     *primitiveset.PrimitiveSet[tink.HybridEncrypt]
	logger monitoring.Logger
}

// compile time assertion that wrappedHybridEncrypt implements the HybridEncrypt interface.
var _ tink.HybridEncrypt = (*wrappedHybridEncrypt)(nil)

func isAEAD(p any) bool {
	if p == nil {
		return false
	}
	_, ok := p.(tink.AEAD)
	return ok
}

func newEncryptPrimitiveSet(ps *primitiveset.PrimitiveSet[tink.HybridEncrypt]) (*wrappedHybridEncrypt, error) {
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
	logger, err := createEncryptLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedHybridEncrypt{
		ps:     ps,
		logger: logger,
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

// Encrypt encrypts the given plaintext binding contextInfo to the resulting ciphertext.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *wrappedHybridEncrypt) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	primary := a.ps.Primary
	ct, err := primary.Primitive.Encrypt(plaintext, contextInfo)
	if err != nil {
		a.logger.LogFailure()
		return nil, err
	}
	a.logger.Log(primary.KeyID, len(plaintext))
	if len(primary.Prefix) == 0 {
		return ct, nil
	}
	output := make([]byte, 0, len(primary.Prefix)+len(ct))
	output = append(output, primary.Prefix...)
	output = append(output, ct...)
	return output, nil
}
