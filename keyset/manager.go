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

package keyset

import (
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/subtle/random"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// Manager manages a Keyset-proto, with convenience methods that rotate, disable, enable or destroy keys.
// Note: It is not thread-safe.
type Manager struct {
	ks                *tinkpb.Keyset
	unavailableKeyIDs map[uint32]bool // set of key IDs that are not available for new keys
}

// NewManager creates a new instance with an empty Keyset.
func NewManager() *Manager {
	ret := new(Manager)
	ret.ks = new(tinkpb.Keyset)
	ret.unavailableKeyIDs = make(map[uint32]bool)
	return ret
}

// NewManagerFromHandle creates a new instance from the given Handle.
func NewManagerFromHandle(kh *Handle) *Manager {
	ret := new(Manager)
	ret.ks = keysetMaterial(kh)
	ret.unavailableKeyIDs = make(map[uint32]bool)
	for _, key := range ret.ks.Key {
		ret.unavailableKeyIDs[key.KeyId] = true
	}
	return ret
}

// Add generates and adds a fresh key using the given key template.
// the key is enabled on creation, but not set to primary.
// It returns the ID of the new key
func (km *Manager) Add(kt *tinkpb.KeyTemplate) (uint32, error) {
	if kt == nil {
		return 0, errors.New("keyset.Manager: key template is nil")
	}
	if kt.OutputPrefixType == tinkpb.OutputPrefixType_UNKNOWN_PREFIX {
		return 0, errors.New("keyset.Manager: unknown output prefix type")
	}
	if km.ks == nil {
		return 0, errors.New("keyset.Manager: cannot add key to nil keyset")
	}
	keyData, err := registry.NewKeyData(kt)
	if err != nil {
		return 0, fmt.Errorf("keyset.Manager: cannot create KeyData: %s", err)
	}
	keyID := km.newRandomKeyID()
	key := &tinkpb.Keyset_Key{
		KeyData:          keyData,
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            keyID,
		OutputPrefixType: kt.OutputPrefixType,
	}
	km.ks.Key = append(km.ks.Key, key)
	return keyID, nil
}

func (km *Manager) getIDForKey(key key.Key) (uint32, error) {
	id, required := key.IDRequirement()
	if !required {
		return km.newRandomKeyID(), nil
	}
	if _, found := km.unavailableKeyIDs[id]; found {
		return 0, fmt.Errorf("keyset already has a key with ID %d", id)
	}
	km.unavailableKeyIDs[id] = true
	return id, nil
}

// AddKey adds key to the keyset and returns the key ID. The added key is
// enabled by default.
func (km *Manager) AddKey(key key.Key) (uint32, error) {
	if key == nil {
		return 0, fmt.Errorf("keyset.Manager: entry must have Key set")
	}
	keySerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		return 0, fmt.Errorf("keyset.Manager: %v", err)
	}
	// This is going to be either an ID requirement or a new random ID.
	keyID, err := km.getIDForKey(key)
	if err != nil {
		return 0, err
	}
	km.ks.Key = append(km.ks.Key, &tinkpb.Keyset_Key{
		KeyId:            keyID,
		Status:           tinkpb.KeyStatusType_ENABLED,
		OutputPrefixType: keySerialization.OutputPrefixType(),
		KeyData:          keySerialization.KeyData(),
	})
	return keyID, nil
}

// AddNewKeyFromParameters generates a new key from parameters, adds the key to
// the keyset, and returns the key ID.
func (km *Manager) AddNewKeyFromParameters(parameters key.Parameters) (uint32, error) {
	keyTemplate, err := protoserialization.SerializeParameters(parameters)
	if err != nil {
		return 0, fmt.Errorf("keyset.Manager: %v", err)
	}
	return km.Add(keyTemplate)
}

// SetPrimary sets the key with given keyID as primary.
// Returns an error if the key is not found or not enabled.
func (km *Manager) SetPrimary(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset.Manager: cannot set primary key to nil keyset")
	}
	for _, key := range km.ks.Key {
		if key.KeyId != keyID {
			continue
		}
		if key.Status == tinkpb.KeyStatusType_ENABLED {
			km.ks.PrimaryKeyId = keyID
			return nil
		}
		return errors.New("keyset.Manager: cannot set key as primary because it's not enabled")

	}
	return fmt.Errorf("keyset.Manager: key with id %d not found", keyID)
}

// Enable will enable the key with given keyID.
// Returns an error if the key is not found or is not enabled or disabled already.
func (km *Manager) Enable(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset.Manager: cannot enable key; nil keyset")
	}
	for i, key := range km.ks.Key {
		if key.KeyId != keyID {
			continue
		}
		if key.Status == tinkpb.KeyStatusType_ENABLED || key.Status == tinkpb.KeyStatusType_DISABLED {
			km.ks.Key[i].Status = tinkpb.KeyStatusType_ENABLED
			return nil
		}
		return fmt.Errorf("keyset.Manager: cannot enable key with id %d with status %s", keyID, key.Status.String())
	}
	return fmt.Errorf("keyset.Manager: key with id %d not found", keyID)
}

// Disable will disable the key with given keyID.
// Returns an error if the key is not found or it is the primary key.
func (km *Manager) Disable(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset.Manager: cannot disable key; nil keyset")
	}
	if km.ks.PrimaryKeyId == keyID {
		return errors.New("keyset.Manager: cannot disable the primary key")
	}
	for i, key := range km.ks.Key {
		if key.KeyId != keyID {
			continue
		}
		if key.Status == tinkpb.KeyStatusType_ENABLED || key.Status == tinkpb.KeyStatusType_DISABLED {
			km.ks.Key[i].Status = tinkpb.KeyStatusType_DISABLED
			return nil
		}
		return fmt.Errorf("keyset.Manager: cannot disable key with id %d with status %s", keyID, key.Status.String())
	}
	return fmt.Errorf("keyset.Manager: key with id %d not found", keyID)
}

// Delete will delete the key with given keyID, removing the key from the keyset entirely.
// Returns an error if the key is not found or it is the primary key.
func (km *Manager) Delete(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset.Manager: cannot delete key, no keyset")
	}
	if km.ks.PrimaryKeyId == keyID {
		return errors.New("keyset.Manager: cannot delete the primary key")
	}
	deleteIdx, found := 0, false
	for i, key := range km.ks.Key {
		if key.KeyId == keyID {
			deleteIdx = i
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("keyset.Manager: key with id %d not found", keyID)
	}
	km.ks.Key = slices.Delete(km.ks.Key, deleteIdx, deleteIdx+1)
	// NOTE: not removing the ID from unavailableKeyIDs on purpose to avoid reusing the keyID right
	// away.
	return nil
}

// Handle creates a new Handle for the managed keyset.
func (km *Manager) Handle() (*Handle, error) {
	// Make a copy of the keyset to keep it
	ks := proto.Clone(km.ks).(*tinkpb.Keyset)
	return newWithOptions(ks)
}

// newRandomKeyID generates a key id that has not been used by any key in the keyset.
func (km *Manager) newRandomKeyID() uint32 {
	for {
		newRandomID := random.GetRandomUint32()
		if _, found := km.unavailableKeyIDs[newRandomID]; !found {
			km.unavailableKeyIDs[newRandomID] = true
			return newRandomID
		}
	}
}
