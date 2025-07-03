// Copyright 2022 Google LLC
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

package keyderivation_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderiver"
	"github.com/tink-crypto/tink-go/v2/keyderivation"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// invalidDeriver returns two keys, but wrappedKeysetDeriver accepts only one.
type invalidDeriver struct{}

var _ keyderivation.KeysetDeriver = (*invalidDeriver)(nil)

func (i *invalidDeriver) DeriveKeyset(salt []byte) (*keyset.Handle, error) {
	manager := keyset.NewManager()
	keyID, err := manager.Add(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, err
	}
	manager.SetPrimary(keyID)
	if _, err = manager.Add(aead.AES256GCMKeyTemplate()); err != nil {
		return nil, err
	}
	return manager.Handle()
}

func TestNewWrappedKeysetDeriverWrongPrimitiveFails(t *testing.T) {
	handle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	if _, err := keyderivation.New(handle); err == nil {
		t.Errorf("keyderivation.New() err = nil, want non-nil")
	}
}

const (
	stubKeysetDeriverURL = "type.googleapis.com/google.crypto.tink.StubKeysetDeriver"
)

type stubKeysetDeriverParams struct{}

var _ key.Parameters = (*stubKeysetDeriverParams)(nil)

func (p *stubKeysetDeriverParams) Equal(_ key.Parameters) bool { return true }
func (p *stubKeysetDeriverParams) HasIDRequirement() bool      { return true }

type stubKeysetDeriverKey struct {
	prefixType    tinkpb.OutputPrefixType
	idRequirement uint32
}

var _ key.Key = (*stubKeysetDeriverKey)(nil)

func (p *stubKeysetDeriverKey) Equal(_ key.Key) bool       { return true }
func (p *stubKeysetDeriverKey) Parameters() key.Parameters { return &stubKeysetDeriverParams{} }
func (p *stubKeysetDeriverKey) IDRequirement() (uint32, bool) {
	return p.idRequirement, p.HasIDRequirement()
}
func (p *stubKeysetDeriverKey) HasIDRequirement() bool {
	return p.prefixType != tinkpb.OutputPrefixType_RAW
}

type stubKeysetDeriverKeySerialization struct{}

var _ protoserialization.KeySerializer = (*stubKeysetDeriverKeySerialization)(nil)

func (s *stubKeysetDeriverKeySerialization) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         stubKeysetDeriverURL,
			Value:           []byte("serialized_key"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		key.(*stubKeysetDeriverKey).prefixType,
		key.(*stubKeysetDeriverKey).idRequirement,
	)
}

type stubKeysetDeriverKeyParser struct{}

var _ protoserialization.KeyParser = (*stubKeysetDeriverKeyParser)(nil)

func (s *stubKeysetDeriverKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := serialization.IDRequirement()
	return &stubKeysetDeriverKey{
		prefixType:    serialization.OutputPrefixType(),
		idRequirement: idRequirement,
	}, nil
}

const (
	derivedKeyURL = "type.googleapis.com/google.crypto.tink.DerivedKey"
)

type derivedKey struct {
	prefixType    tinkpb.OutputPrefixType
	idRequirement uint32
	value         []byte
}

var _ key.Key = (*derivedKey)(nil)

func (p *derivedKey) Equal(_ key.Key) bool       { return true }
func (p *derivedKey) Parameters() key.Parameters { return &stubKeysetDeriverParams{} }
func (p *derivedKey) IDRequirement() (uint32, bool) {
	return p.idRequirement, p.HasIDRequirement()
}
func (p *derivedKey) HasIDRequirement() bool {
	return p.prefixType != tinkpb.OutputPrefixType_RAW
}

type stubLegacyKeyDeriver struct{}

var _ keyderiver.KeyDeriver = (*stubLegacyKeyDeriver)(nil)

func (s *stubLegacyKeyDeriver) DeriveKey(salt []byte) (key.Key, error) {
	return &derivedKey{
		value:         slices.Concat(salt, []byte("_raw_derived_key")),
		prefixType:    tinkpb.OutputPrefixType_RAW,
		idRequirement: 0,
	}, nil
}

type derivedKeySerializer struct{}

var _ protoserialization.KeySerializer = (*derivedKeySerializer)(nil)

func (s *derivedKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         derivedKeyURL,
			Value:           key.(*derivedKey).value,
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		key.(*derivedKey).prefixType,
		key.(*derivedKey).idRequirement,
	)
}

type derivedKeyParser struct{}

var _ protoserialization.KeyParser = (*derivedKeyParser)(nil)

func (s *derivedKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := serialization.IDRequirement()
	return &derivedKey{
		prefixType:    serialization.OutputPrefixType(),
		idRequirement: idRequirement,
		value:         serialization.KeyData().GetValue(),
	}, nil
}

type stubKeyDeriverKeyManager struct{}

var _ registry.KeyManager = (*stubKeyDeriverKeyManager)(nil)

func (km *stubKeyDeriverKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeyDeriverKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeyDeriverKeyManager) DoesSupport(keyURL string) bool {
	return keyURL == stubKeysetDeriverURL
}
func (km *stubKeyDeriverKeyManager) TypeURL() string { return stubKeysetDeriverURL }
func (km *stubKeyDeriverKeyManager) Primitive(_ []byte) (any, error) {
	return &stubLegacyKeyDeriver{}, nil
}

func TestPrimitiveFactory_New_FailsIfNoKeyManagerRegistered(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeysetDeriverURL)
	defer protoserialization.UnregisterKeySerializer[*stubKeysetDeriverKey]()

	if err := protoserialization.RegisterKeyParser(stubKeysetDeriverURL, &stubKeysetDeriverKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKeysetDeriverKey](&stubKeysetDeriverKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	// Create a keyset with a single key.
	km := keyset.NewManager()
	keyID, err := km.AddKey(&stubKeysetDeriverKey{tinkpb.OutputPrefixType_TINK, 0x1234})
	if err != nil {
		t.Fatalf("km.AddKey() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	if _, err := keyderivation.New(handle); err == nil {
		t.Fatalf("keyderivation.New() err = nil, want non-nil")
	}
}

func TestPrimitiveFactory_UsesRawPrimitives(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeysetDeriverURL)
	defer protoserialization.UnregisterKeySerializer[*stubKeysetDeriverKey]()
	defer protoserialization.UnregisterKeyParser(derivedKeyURL)
	defer protoserialization.UnregisterKeySerializer[*derivedKey]()

	if err := protoserialization.RegisterKeyParser(stubKeysetDeriverURL, &stubKeysetDeriverKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKeysetDeriverKey](&stubKeysetDeriverKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeyParser(derivedKeyURL, &derivedKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*derivedKey](&derivedKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	// Register the key manager.
	if err := registry.RegisterKeyManager(&stubKeyDeriverKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name       string
		key        *stubKeysetDeriverKey
		wantKeyset *tinkpb.Keyset
	}{
		{
			name: "TINK",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_TINK, 0x1234},
			wantKeyset: testutil.NewKeyset(0x1234, []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         derivedKeyURL,
						Value:           []byte("a_very_unique_salt_raw_derived_key"),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            0x1234,
					OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				},
			}),
		},
		{
			name: "RAW",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_RAW, 0},
			wantKeyset: testutil.NewKeyset(0x12345678, []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         derivedKeyURL,
						Value:           []byte("a_very_unique_salt_raw_derived_key"),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            0x12345678,
					OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				},
			}),
		},
		{
			name: "CRUNCHY",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_CRUNCHY, 0x1234},
			wantKeyset: testutil.NewKeyset(0x1234, []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         derivedKeyURL,
						Value:           []byte("a_very_unique_salt_raw_derived_key"),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            0x1234,
					OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
				},
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create a keyset with a single key.
			km := keyset.NewManager()

			var opts []keyset.KeyOpts
			if !tc.key.HasIDRequirement() {
				opts = append(opts, keyset.WithFixedID(0x12345678))
			}

			keyID, err := km.AddKeyWithOpts(tc.key, internalapi.Token{}, opts...)
			if err != nil {
				t.Fatalf("km.AddKeyWithOpts() err = %v, want nil", err)
			}
			if err := km.SetPrimary(keyID); err != nil {
				t.Fatalf("km.SetPrimary() err = %v, want nil", err)
			}
			handle, err := km.Handle()
			if err != nil {
				t.Fatalf("km.Handle() err = %v, want nil", err)
			}

			keysetDeriver, err := keyderivation.New(handle)
			if err != nil {
				t.Fatalf("keyderivation.New() err = %v, want nil", err)
			}

			gotHandle, err := keysetDeriver.DeriveKeyset([]byte("a_very_unique_salt"))
			if err != nil {
				t.Fatalf("keysetDeriver.DeriveKeyset() err = %v, want nil", err)
			}
			got := testkeyset.KeysetMaterial(gotHandle)
			if diff := cmp.Diff(tc.wantKeyset, got, protocmp.Transform()); diff != "" {
				t.Errorf("keysetDeriver.DeriveKeyset() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

type fullKeyDeriver struct {
	k *stubKeysetDeriverKey
}

func (s *fullKeyDeriver) DeriveKey(salt []byte) (key.Key, error) {
	return &derivedKey{
		value:         slices.Concat(salt, []byte("_full_derived_key")),
		prefixType:    s.k.prefixType,
		idRequirement: s.k.idRequirement,
	}, nil
}

func TestPrimitiveFactory_UsesFullPrimitives(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeysetDeriverURL)
	defer protoserialization.UnregisterKeySerializer[*stubKeysetDeriverKey]()
	defer protoserialization.UnregisterKeyParser(derivedKeyURL)
	defer protoserialization.UnregisterKeySerializer[*derivedKey]()
	defer registryconfig.UnregisterPrimitiveConstructor[*stubKeysetDeriverKey]()

	if err := protoserialization.RegisterKeyParser(stubKeysetDeriverURL, &stubKeysetDeriverKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKeysetDeriverKey](&stubKeysetDeriverKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeyParser(derivedKeyURL, &derivedKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*derivedKey](&derivedKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	if err := registryconfig.RegisterPrimitiveConstructor[*stubKeysetDeriverKey](func(k key.Key) (any, error) {
		that, ok := k.(*stubKeysetDeriverKey)
		if !ok {
			return nil, fmt.Errorf("key is not a stubKeysetDeriverKey")
		}
		return &fullKeyDeriver{k: that}, nil
	}); err != nil {
		t.Fatalf("registryconfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name       string
		key        *stubKeysetDeriverKey
		wantKeyset *tinkpb.Keyset
	}{
		{
			name: "TINK",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_TINK, 0x1234},
			wantKeyset: testutil.NewKeyset(0x1234, []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         derivedKeyURL,
						Value:           []byte("a_very_unique_salt_full_derived_key"),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            0x1234,
					OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				},
			}),
		},
		{
			name: "RAW",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_RAW, 0},
			wantKeyset: testutil.NewKeyset(0x12345678, []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         derivedKeyURL,
						Value:           []byte("a_very_unique_salt_full_derived_key"),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            0x12345678,
					OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				},
			}),
		},
		{
			name: "CRUNCHY",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_CRUNCHY, 0x1234},
			wantKeyset: testutil.NewKeyset(0x1234, []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         derivedKeyURL,
						Value:           []byte("a_very_unique_salt_full_derived_key"),
						KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					},
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            0x1234,
					OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
				},
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create a keyset with a single key.
			km := keyset.NewManager()

			var opts []keyset.KeyOpts
			if !tc.key.HasIDRequirement() {
				opts = append(opts, keyset.WithFixedID(0x12345678))
			}

			keyID, err := km.AddKeyWithOpts(tc.key, internalapi.Token{}, opts...)
			if err != nil {
				t.Fatalf("km.AddKeyWithOpts() err = %v, want nil", err)
			}
			if err := km.SetPrimary(keyID); err != nil {
				t.Fatalf("km.SetPrimary() err = %v, want nil", err)
			}
			handle, err := km.Handle()
			if err != nil {
				t.Fatalf("km.Handle() err = %v, want nil", err)
			}

			keysetDeriver, err := keyderivation.New(handle)
			if err != nil {
				t.Fatalf("keyderivation.New() err = %v, want nil", err)
			}

			gotHandle, err := keysetDeriver.DeriveKeyset([]byte("a_very_unique_salt"))
			if err != nil {
				t.Fatalf("keysetDeriver.DeriveKeyset() err = %v, want nil", err)
			}
			got := testkeyset.KeysetMaterial(gotHandle)

			if diff := cmp.Diff(tc.wantKeyset, got, protocmp.Transform()); diff != "" {
				t.Errorf("keysetDeriver.DeriveKeyset() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPrimitiveFactory_MultipleKeys_UsesFullPrimitives(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeysetDeriverURL)
	defer protoserialization.UnregisterKeySerializer[*stubKeysetDeriverKey]()
	defer protoserialization.UnregisterKeyParser(derivedKeyURL)
	defer protoserialization.UnregisterKeySerializer[*derivedKey]()
	defer registryconfig.UnregisterPrimitiveConstructor[*stubKeysetDeriverKey]()

	if err := protoserialization.RegisterKeyParser(stubKeysetDeriverURL, &stubKeysetDeriverKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKeysetDeriverKey](&stubKeysetDeriverKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeyParser(derivedKeyURL, &derivedKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*derivedKey](&derivedKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	if err := registryconfig.RegisterPrimitiveConstructor[*stubKeysetDeriverKey](func(k key.Key) (any, error) {
		that, ok := k.(*stubKeysetDeriverKey)
		if !ok {
			return nil, fmt.Errorf("key is not a stubKeysetDeriverKey")
		}
		return &fullKeyDeriver{k: that}, nil
	}); err != nil {
		t.Fatalf("registryconfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	km := keyset.NewManager()

	keyID, err := km.AddKey(&stubKeysetDeriverKey{tinkpb.OutputPrefixType_TINK, 0x1234})
	if err != nil {
		t.Fatalf("km.AddKey() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	if _, err := km.AddKeyWithOpts(&stubKeysetDeriverKey{tinkpb.OutputPrefixType_TINK, 0x2222}, internalapi.Token{}, keyset.WithStatus(keyset.Disabled)); err != nil {
		t.Fatalf("km.AddKeyWithOpts() err = %v, want nil", err)
	}
	if _, err := km.AddKeyWithOpts(&stubKeysetDeriverKey{tinkpb.OutputPrefixType_CRUNCHY, 0x2345}, internalapi.Token{}, keyset.WithStatus(keyset.Enabled)); err != nil {
		t.Fatalf("km.AddKeyWithOpts() err = %v, want nil", err)
	}
	if _, err := km.AddKeyWithOpts(&stubKeysetDeriverKey{tinkpb.OutputPrefixType_RAW, 0}, internalapi.Token{}, keyset.WithStatus(keyset.Destroyed)); err != nil {
		t.Fatalf("km.AddKeyWithOpts() err = %v, want nil", err)
	}

	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	keysetDeriver, err := keyderivation.New(handle)
	if err != nil {
		t.Fatalf("keyderivation.New() err = %v, want nil", err)
	}

	gotHandle, err := keysetDeriver.DeriveKeyset([]byte("a_very_unique_salt"))
	if err != nil {
		t.Fatalf("keysetDeriver.DeriveKeyset() err = %v, want nil", err)
	}
	got := testkeyset.KeysetMaterial(gotHandle)

	// Only the enabled keys are in the derived keyset.
	want := testutil.NewKeyset(0x1234, []*tinkpb.Keyset_Key{
		{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         derivedKeyURL,
				Value:           []byte("a_very_unique_salt_full_derived_key"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			Status:           tinkpb.KeyStatusType_ENABLED,
			KeyId:            0x1234,
			OutputPrefixType: tinkpb.OutputPrefixType_TINK,
		},
		{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         derivedKeyURL,
				Value:           []byte("a_very_unique_salt_full_derived_key"),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			Status:           tinkpb.KeyStatusType_ENABLED,
			KeyId:            0x2345,
			OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
		},
	})
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("keysetDeriver.DeriveKeyset() returned unexpected diff (-want +got):\n%s", diff)
	}
}

type failingKeyDeriver struct{}

func (s *failingKeyDeriver) DeriveKey(salt []byte) (key.Key, error) {
	return nil, fmt.Errorf("failingKeyDeriver.DeriveKey() failed")
}

func TestPrimitiveFactory_KeysetDeriverFailsIfFullPrimitiveFails(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeysetDeriverURL)
	defer protoserialization.UnregisterKeySerializer[*stubKeysetDeriverKey]()
	defer protoserialization.UnregisterKeyParser(derivedKeyURL)
	defer protoserialization.UnregisterKeySerializer[*derivedKey]()
	defer registryconfig.UnregisterPrimitiveConstructor[*stubKeysetDeriverKey]()

	if err := protoserialization.RegisterKeyParser(stubKeysetDeriverURL, &stubKeysetDeriverKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKeysetDeriverKey](&stubKeysetDeriverKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeyParser(derivedKeyURL, &derivedKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*derivedKey](&derivedKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	if err := registryconfig.RegisterPrimitiveConstructor[*stubKeysetDeriverKey](func(k key.Key) (any, error) {
		return &failingKeyDeriver{}, nil
	}); err != nil {
		t.Fatalf("registryconfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	// Create a keyset with a single key.
	km := keyset.NewManager()
	keyID, err := km.AddKey(&stubKeysetDeriverKey{tinkpb.OutputPrefixType_RAW, 0})
	if err != nil {
		t.Fatalf("km.AddKey() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	keysetDeriver, err := keyderivation.New(handle)
	if err != nil {
		t.Fatalf("keyderivation.New() err = %v, want nil", err)
	}

	if _, err := keysetDeriver.DeriveKeyset([]byte("a_very_unique_salt")); err == nil {
		t.Errorf("keysetDeriver.DeriveKeyset() err = %v, want nil", err)
	}
}
