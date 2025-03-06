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
	"bytes"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// NewHybridDecrypt returns an HybridDecrypt primitive from the given keyset handle.
func NewHybridDecrypt(handle *keyset.Handle) (tink.HybridDecrypt, error) {
	ps, err := keyset.Primitives[tink.HybridDecrypt](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("hybrid_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedHybridDecrypt(ps)
}

type fullHybridDecryptAdapter struct {
	rawHybridDecrypt tink.HybridDecrypt
	prefix           []byte
}

var _ tink.HybridDecrypt = (*fullHybridDecryptAdapter)(nil)

func (d *fullHybridDecryptAdapter) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	// This is called by `wrappedHybridDecrypt.Decrypt`, which selects the
	// correct decrypter based on the prefix; if the prefix is not correct,
	// this is a bug.
	if len(ciphertext) < len(d.prefix) {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if !bytes.Equal(d.prefix, ciphertext[:len(d.prefix)]) {
		return nil, fmt.Errorf("ciphertext does not start with the expected prefix %x", d.prefix)
	}
	return d.rawHybridDecrypt.Decrypt(ciphertext[len(d.prefix):], contextInfo)
}

type decrypterAndID struct {
	decrypter tink.HybridDecrypt
	keyID     uint32
}

var _ tink.HybridDecrypt = (*decrypterAndID)(nil)

func (d *decrypterAndID) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	return d.decrypter.Decrypt(ciphertext, contextInfo)
}

// wrappedHybridDecrypt is an HybridDecrypt implementation that uses the underlying primitive set
// for decryption.
type wrappedHybridDecrypt struct {
	decrypters map[string][]decrypterAndID
	logger     monitoring.Logger
}

// compile time assertion that wrappedHybridDecrypt implements the HybridDecrypt interface.
var _ tink.HybridDecrypt = (*wrappedHybridDecrypt)(nil)

func newWrappedHybridDecrypt(ps *primitiveset.PrimitiveSet[tink.HybridDecrypt]) (*wrappedHybridDecrypt, error) {
	// Make sure the primitives do not implement tink.AEAD.
	decrypters := make(map[string][]decrypterAndID)

	if isAEAD(ps.Primary.Primitive) || isAEAD(ps.Primary.FullPrimitive) {
		return nil, fmt.Errorf("hybrid_factory: primary primitive must NOT implement tink.AEAD")
	}
	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if isAEAD(p.Primitive) || isAEAD(p.FullPrimitive) {
				return nil, fmt.Errorf("hybrid_factory: primitive must NOT implement tink.AEAD")
			}
			fullPrimitive := p.FullPrimitive
			if fullPrimitive == nil {
				fullPrimitive = &fullHybridDecryptAdapter{
					rawHybridDecrypt: p.Primitive,
					prefix:           []byte(p.Prefix),
				}
			}
			decrypters[p.Prefix] = append(decrypters[p.Prefix], decrypterAndID{
				decrypter: fullPrimitive,
				keyID:     p.KeyID,
			})
		}
	}
	logger, err := createDecryptLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedHybridDecrypt{
		decrypters: decrypters,
		logger:     logger,
	}, nil
}

func createDecryptLogger(ps *primitiveset.PrimitiveSet[tink.HybridDecrypt]) (monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	return internalregistry.GetMonitoringClient().NewLogger(&monitoring.Context{
		KeysetInfo:  keysetInfo,
		Primitive:   "hybrid_decrypt",
		APIFunction: "decrypt",
	})
}

// Decrypt decrypts the given ciphertext, verifying the integrity of contextInfo.
// It returns the corresponding plaintext if the ciphertext is authenticated.
func (a *wrappedHybridDecrypt) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	// Try non-raw keys.
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(ciphertext) > prefixSize {
		prefix := ciphertext[:prefixSize]
		decryptersForPrefix, found := a.decrypters[string(prefix)]
		if found {
			for _, verifier := range decryptersForPrefix {
				pt, err := verifier.Decrypt(ciphertext, contextInfo)
				if err == nil {
					a.logger.Log(verifier.keyID, len(ciphertext[len(prefix):]))
					return pt, nil
				}
			}
		}
	}
	// Try raw keys.
	rawDecrypters, found := a.decrypters[cryptofmt.RawPrefix]
	if found {
		for _, decrypter := range rawDecrypters {
			pt, err := decrypter.Decrypt(ciphertext, contextInfo)
			if err == nil {
				a.logger.Log(decrypter.keyID, len(ciphertext))
				return pt, nil
			}
		}
	}
	// Nothing worked.
	a.logger.LogFailure()
	return nil, fmt.Errorf("hybrid_factory: decryption failed")
}
