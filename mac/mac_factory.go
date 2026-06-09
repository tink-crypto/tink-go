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

package mac

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/prefixmap"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<(intSize-1) - 1
)

// NewWithConfig creates a [tink.MAC] primitive from the given [keyset.Handle]
// and [keyset.Config].
func NewWithConfig(handle *keyset.Handle, c keyset.Config) (tink.MAC, error) {
	primitives := prefixmap.New[macAndKeyID]()
	var primary macAndKeyID
	for entry := range factoryutil.EnabledUnmonitoredEntries(handle) {
		p, isLegacyPrimitive, err := factoryutil.PrimitiveFromKey[tink.MAC](entry.Key(), c)
		if err != nil {
			return nil, err
		}
		outputPrefix, err := factoryutil.OutputPrefix(entry.Key())
		if err != nil {
			return nil, err
		}

		if isLegacyPrimitive {
			protoKey, err := protoserialization.SerializeKey(entry.Key())
			if err != nil {
				return nil, err
			}
			hasLegacyPrefix := protoKey.OutputPrefixType() == tinkpb.OutputPrefixType_LEGACY
			p = &fullMACAdapter{
				rawPrimitive:    p,
				prefix:          outputPrefix,
				hasLegacyPrefix: hasLegacyPrefix,
			}
		}
		primitives.Insert(string(outputPrefix), macAndKeyID{
			primitive: p,
			keyID:     entry.KeyID(),
		})
		if entry.IsPrimary() {
			primary = macAndKeyID{
				primitive: p,
				keyID:     entry.KeyID(),
			}
		}
	}

	computeLogger, verifyLogger, err := createLoggers(handle)
	if err != nil {
		return nil, err
	}
	return &wrappedMAC{
		primary:       primary,
		primitives:    primitives,
		computeLogger: computeLogger,
		verifyLogger:  verifyLogger,
	}, nil
}

// New creates a [tink.MAC] primitive from the given [keyset.Handle] using the
// default set of available primitives.
func New(handle *keyset.Handle) (tink.MAC, error) {
	return NewWithConfig(handle, &registryconfig.RegistryConfig{})
}

type macAndKeyID struct {
	primitive tink.MAC
	keyID     uint32
}

var _ (tink.MAC) = (*macAndKeyID)(nil)

func (m *macAndKeyID) ComputeMAC(data []byte) ([]byte, error) {
	return m.primitive.ComputeMAC(data)
}

func (m *macAndKeyID) VerifyMAC(mac, data []byte) error {
	return m.primitive.VerifyMAC(mac, data)
}

// fullMACAdapter is a [tink.MAC] implementation that turns a RAW MAC primitive
// into a full MAC primitive.
type fullMACAdapter struct {
	rawPrimitive    tink.MAC
	prefix          []byte
	hasLegacyPrefix bool
}

var _ (tink.MAC) = (*fullMACAdapter)(nil)

func (m *fullMACAdapter) data(data []byte) ([]byte, error) {
	if m.hasLegacyPrefix {
		d := data
		if len(d) == maxInt {
			return nil, fmt.Errorf("data too long")
		}
		return append(d, byte(0)), nil
	}
	return data, nil
}

func (m *fullMACAdapter) ComputeMAC(data []byte) ([]byte, error) {
	d, err := m.data(data)
	if err != nil {
		return nil, err
	}
	mac, err := m.rawPrimitive.ComputeMAC(d)
	if err != nil {
		return nil, err
	}
	return slices.Concat(m.prefix, mac), nil
}

func (m *fullMACAdapter) VerifyMAC(mac, data []byte) error {
	if len(mac) < len(m.prefix) {
		return fmt.Errorf("invalid mac")
	}
	if !bytes.Equal(mac[:len(m.prefix)], m.prefix) {
		return fmt.Errorf("invalid prefix")
	}
	d, err := m.data(data)
	if err != nil {
		return err
	}
	return m.rawPrimitive.VerifyMAC(mac[len(m.prefix):], d)
}

// wrappedMAC is a [tink.MAC] implementation that uses a set of [tink.MAC]
// primitives to compute and verify MACs.
//
// When computing a MAC, the wrappedMAC uses the primary primitive. When
// verifying a MAC, the wrappedMAC uses the key ID in the MAC to find the
// primitive that should be used for verification.
type wrappedMAC struct {
	primary    macAndKeyID
	primitives *prefixmap.PrefixMap[macAndKeyID]

	computeLogger monitoring.Logger
	verifyLogger  monitoring.Logger
}

var _ (tink.MAC) = (*wrappedMAC)(nil)

func createLoggers(kh *keyset.Handle) (monitoring.Logger, monitoring.Logger, error) {
	factory, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		return nil, nil, err
	}
	computeLogger, err := factory.CreateFor("mac", "compute")
	if err != nil {
		return nil, nil, err
	}
	verifyLogger, err := factory.CreateFor("mac", "verify")
	if err != nil {
		return nil, nil, err
	}
	return computeLogger, verifyLogger, nil
}

// ComputeMAC calculates a MAC over the given data using the primary primitive
// and returns the concatenation of the primary's identifier and the calculated mac.
func (m *wrappedMAC) ComputeMAC(data []byte) ([]byte, error) {
	mac, err := m.primary.ComputeMAC(data)
	if err != nil {
		m.computeLogger.LogFailure()
		return nil, err
	}
	m.computeLogger.Log(m.primary.keyID, len(data))
	return mac, nil
}

func (m *wrappedMAC) tryVerifyMAC(mac []byte, data []byte, it *prefixmap.Iterator[macAndKeyID]) bool {
	for primitive, ok := it.Next(); ok; primitive, ok = it.Next() {
		if err := primitive.VerifyMAC(mac, data); err == nil {
			m.verifyLogger.Log(primitive.keyID, len(data))
			return true
		}
	}
	return false
}

// VerifyMAC verifies whether the given mac is a correct authentication code
// for the given data.
func (m *wrappedMAC) VerifyMAC(mac, data []byte) error {
	// This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
	// clearly insecure, thus should be discouraged.
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(mac) <= prefixSize {
		m.verifyLogger.LogFailure()
		return fmt.Errorf("mac_factory: invalid mac")
	}
	// Try non raw keys.
	it := m.primitives.PrimitivesMatchingPrefix(mac[:prefixSize])
	if m.tryVerifyMAC(mac, data, it) {
		return nil
	}
	// Try raw keys.
	it = m.primitives.PrimitivesMatchingPrefix(nil)
	if m.tryVerifyMAC(mac, data, it) {
		return nil
	}
	// nothing worked
	m.verifyLogger.LogFailure()
	return fmt.Errorf("mac_factory: invalid mac")
}
