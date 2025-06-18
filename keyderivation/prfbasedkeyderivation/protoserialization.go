// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prfbasedkeyderivation

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	prfderpb "github.com/tink-crypto/tink-go/v2/proto/prf_based_deriver_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	typeURL = "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"
)

type keyParser struct{}

var _ protoserialization.KeyParser = (*keyParser)(nil)

// ParseKey converts a proto serialized key into a [prfbasedkeyderivation.Key] object.
func (p *keyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if keySerialization.KeyData().GetTypeUrl() != typeURL {
		return nil, fmt.Errorf("prfbasedkeyderivation: unexpected type URL: got %q, want %q", keySerialization.KeyData().GetTypeUrl(), typeURL)
	}
	if keySerialization.KeyData().GetKeyMaterialType() != tinkpb.KeyData_SYMMETRIC {
		return nil, fmt.Errorf("prfbasedkeyderivation: invalid key material type: got %v, want %v", keySerialization.KeyData().GetKeyMaterialType(), tinkpb.KeyData_SYMMETRIC)
	}

	protoKey := new(prfderpb.PrfBasedDeriverKey)
	if err := proto.Unmarshal(keySerialization.KeyData().GetValue(), protoKey); err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: failed to unmarshal key proto: %w", err)
	}
	// Version check for the key proto itself.
	if protoKey.GetVersion() != 0 {
		return nil, fmt.Errorf("prfbasedkeyderivation: unsupported key version %d", protoKey.GetVersion())
	}
	if protoKey.GetParams().GetDerivedKeyTemplate().GetOutputPrefixType() != keySerialization.OutputPrefixType() {
		return nil, fmt.Errorf("prfbasedkeyderivation: inconsistent output prefix type: got %v, want %v", protoKey.GetParams().GetDerivedKeyTemplate().GetOutputPrefixType(), keySerialization.OutputPrefixType())
	}

	derivedKeyParameters, err := protoserialization.ParseParameters(protoKey.GetParams().GetDerivedKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: failed to parse derived key parameters: %w", err)
	}

	prfKeyProtoSerialization, err := protoserialization.NewKeySerialization(protoKey.GetPrfKey(), tinkpb.OutputPrefixType_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: failed to create PRF key proto serialization: %w", err)
	}
	prfKey, err := protoserialization.ParseKey(prfKeyProtoSerialization)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: failed to parse PRF key: %w", err)
	}

	params, err := NewParameters(prfKey.Parameters(), derivedKeyParameters)
	if err != nil {
		return nil, fmt.Errorf("prfbasedkeyderivation: failed to create parameters: %w", err)
	}
	keyID, _ := keySerialization.IDRequirement()
	return NewKey(params, prfKey, keyID)
}
