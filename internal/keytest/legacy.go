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

package keytest

import (
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/tinkerror"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	testonlypb "github.com/tink-crypto/tink-go/v2/proto/test_only_key_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// LegacyKeyTypeURL is the type URL of test-only legacy keys.
//
// This key type never has a registered proto serialization: its keys are
// always parsed as fallback proto keys, and their primitives are always
// created by the key manager registered in the global registry. Use it to test
// the legacy key manager code paths.
const LegacyKeyTypeURL = "type.googleapis.com/google.crypto.tink.TestOnlyLegacyKey"

const legacyKeyVersion = 0

// legacyKeyManager is a [registry.KeyManager] for test-only legacy keys.
type legacyKeyManager struct{}

var _ registry.KeyManager = (*legacyKeyManager)(nil)

// Primitive creates a [testutil.DummyAEAD] for the given serialized
// TestOnlyLegacyKey proto.
//
// The returned primitive is not a full primitive: it does not add the output
// prefix to the ciphertexts.
func (km *legacyKeyManager) Primitive(serializedKey []byte) (any, error) {
	key := new(testonlypb.TestOnlyLegacyKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, fmt.Errorf("keytest: invalid legacy key: %v", err)
	}
	if key.GetVersion() != legacyKeyVersion {
		return nil, fmt.Errorf("keytest: unsupported legacy key version: got %d, want %d", key.GetVersion(), legacyKeyVersion)
	}
	if len(key.GetKeyValue()) != keySizeInBytes {
		return nil, fmt.Errorf("keytest: invalid legacy key size: got %d, want %d", len(key.GetKeyValue()), keySizeInBytes)
	}
	return &testutil.DummyAEAD{Name: hex.EncodeToString(key.GetKeyValue())}, nil
}

// NewKey creates a new TestOnlyLegacyKey proto according to the given
// serialized TestOnlyKeyFormat proto.
func (km *legacyKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	format := new(testonlypb.TestOnlyKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, format); err != nil {
		return nil, fmt.Errorf("keytest: invalid legacy key format: %v", err)
	}
	if format.GetKeySize() != keySizeInBytes {
		return nil, fmt.Errorf("keytest: unsupported legacy key size: got %d, want %d", format.GetKeySize(), keySizeInBytes)
	}
	return &testonlypb.TestOnlyLegacyKey{
		Version:  legacyKeyVersion,
		KeyValue: random.GetRandomBytes(keySizeInBytes),
	}, nil
}

// NewKeyData creates a new KeyData according to the given serialized
// TestOnlyKeyFormat proto.
func (km *legacyKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         LegacyKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport returns true iff typeURL is [LegacyKeyTypeURL].
func (km *legacyKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == LegacyKeyTypeURL
}

// TypeURL returns [LegacyKeyTypeURL].
func (km *legacyKeyManager) TypeURL() string { return LegacyKeyTypeURL }

// LegacyKeyTemplate returns a key template for test-only legacy keys with the
// given output prefix type.
//
// There are no parameters for test-only legacy keys, so this template is the
// only way to generate them.
func LegacyKeyTemplate(outputPrefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	serializedFormat, err := proto.Marshal(&testonlypb.TestOnlyKeyFormat{KeySize: keySizeInBytes})
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          LegacyKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: outputPrefixType,
	}
}
