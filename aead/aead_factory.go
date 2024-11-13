// Copyright 2018 Google LLC
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

package aead

import (
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// New returns an AEAD primitive from the given keyset handle.
func New(handle *keyset.Handle) (tink.AEAD, error) {
	ps, err := handle.Primitives(internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("aead_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedAead(ps)
}

// NewWithConfig creates an AEAD primitive from the given [keyset.Handle] using
// the provided [Config].
func NewWithConfig(handle *keyset.Handle, config keyset.Config) (tink.AEAD, error) {
	ps, err := handle.Primitives(internalapi.Token{}, keyset.WithConfig(config))
	if err != nil {
		return nil, fmt.Errorf("aead_factory: cannot obtain primitive set with config: %s", err)
	}
	return newWrappedAead(ps)
}

// wrappedAead is an AEAD implementation that uses the underlying primitive set for encryption
// and decryption.
type wrappedAead struct {
	ps        *primitiveset.PrimitiveSet
	encLogger monitoring.Logger
	decLogger monitoring.Logger
}

// aeadPrimitiveAdapter is an adapter that turns a non-full [tink.AEAD]
// primitive into a full [tink.AEAD] primitive.
type fullAEADPrimitiveAdapter struct {
	primitive tink.AEAD
	prefix    []byte
}

func (a *fullAEADPrimitiveAdapter) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	ct, err := a.primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		return nil, err
	}
	return slices.Concat(a.prefix, ct), nil
}

func (a *fullAEADPrimitiveAdapter) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.primitive.Decrypt(ciphertext[len(a.prefix):], associatedData)
}

// getFullPrimitive returns a full [tink.AEAD] from the given
// [primitiveset.Entry].
func getFullPrimitive(entry *primitiveset.Entry) (tink.AEAD, error) {
	if entry.FullPrimitive != nil {
		a, ok := (entry.FullPrimitive).(tink.AEAD)
		if !ok {
			return nil, fmt.Errorf("aead_factory: not an AEAD primitive")
		}
		return a, nil
	}
	a, ok := (entry.Primitive).(tink.AEAD)
	if !ok {
		return nil, fmt.Errorf("aead_factory: not an AEAD primitive")
	}
	return &fullAEADPrimitiveAdapter{primitive: a, prefix: []byte(entry.Prefix)}, nil
}

func newWrappedAead(ps *primitiveset.PrimitiveSet) (*wrappedAead, error) {
	if _, err := getFullPrimitive(ps.Primary); err != nil {
		return nil, err
	}
	for _, entries := range ps.Entries {
		for _, entry := range entries {
			if _, err := getFullPrimitive(entry); err != nil {
				return nil, err
			}
		}
	}
	encLogger, decLogger, err := createLoggers(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedAead{
		ps:        ps,
		encLogger: encLogger,
		decLogger: decLogger,
	}, nil
}

func createLoggers(ps *primitiveset.PrimitiveSet) (monitoring.Logger, monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, &monitoringutil.DoNothingLogger{}, nil
	}
	client := internalregistry.GetMonitoringClient()
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, nil, err
	}
	encLogger, err := client.NewLogger(&monitoring.Context{
		Primitive:   "aead",
		APIFunction: "encrypt",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, nil, err
	}
	decLogger, err := client.NewLogger(&monitoring.Context{
		Primitive:   "aead",
		APIFunction: "decrypt",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, nil, err
	}
	return encLogger, decLogger, nil
}

// Encrypt encrypts the given plaintext with the given associatedData.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *wrappedAead) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	primary := a.ps.Primary
	p, err := getFullPrimitive(primary)
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(plaintext, associatedData)
	if err != nil {
		a.encLogger.LogFailure()
		return nil, err
	}
	a.encLogger.Log(primary.KeyID, len(plaintext))
	return ct, nil
}

// Decrypt decrypts the given ciphertext and authenticates it with the given
// associatedData. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (a *wrappedAead) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	// try non-raw keys
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(ciphertext) > prefixSize {
		prefix := ciphertext[:prefixSize]
		entries, err := a.ps.EntriesForPrefix(string(prefix))
		if err == nil {
			for _, entry := range entries {
				p, err := getFullPrimitive(entry)
				if err != nil {
					return nil, err
				}
				pt, err := p.Decrypt(ciphertext, associatedData)
				if err == nil {
					numBytes := len(ciphertext[prefixSize:])
					a.decLogger.Log(entry.KeyID, numBytes)
					return pt, nil
				}
			}
		}
	}
	// try raw keys
	entries, err := a.ps.RawEntries()
	if err == nil {
		for _, entry := range entries {
			p, err := getFullPrimitive(entry)
			if err != nil {
				return nil, err
			}
			pt, err := p.Decrypt(ciphertext, associatedData)
			if err == nil {
				a.decLogger.Log(entry.KeyID, len(ciphertext))
				return pt, nil
			}
		}
	}
	// nothing worked
	a.decLogger.LogFailure()
	return nil, fmt.Errorf("aead_factory: decryption failed")
}
