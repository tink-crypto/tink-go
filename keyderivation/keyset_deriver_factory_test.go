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
	"github.com/tink-crypto/tink-go/v2/key"
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

type stubLegacyKeysetDeriver struct{}

var _ keyderivation.KeysetDeriver = (*stubLegacyKeysetDeriver)(nil)

func (s *stubLegacyKeysetDeriver) DeriveKeyset(salt []byte) (*keyset.Handle, error) {
	ks := testutil.NewKeyset(0, []*tinkpb.Keyset_Key{
		{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         stubKeysetDeriverURL,
				Value:           slices.Concat(salt, []byte("_derived_key")),
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			},
			Status:           tinkpb.KeyStatusType_ENABLED,
			KeyId:            0,
			OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		},
	})
	return testkeyset.NewHandle(ks)
}

type stubKeysetDeriverKeyManager struct{}

var _ registry.KeyManager = (*stubKeysetDeriverKeyManager)(nil)

func (km *stubKeysetDeriverKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeysetDeriverKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeysetDeriverKeyManager) DoesSupport(keyURL string) bool {
	return keyURL == stubKeysetDeriverURL
}
func (km *stubKeysetDeriverKeyManager) TypeURL() string { return stubKeysetDeriverURL }
func (km *stubKeysetDeriverKeyManager) Primitive(_ []byte) (any, error) {
	return &stubLegacyKeysetDeriver{}, nil
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

	if err := protoserialization.RegisterKeyParser(stubKeysetDeriverURL, &stubKeysetDeriverKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKeysetDeriverKey](&stubKeysetDeriverKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	// Register the key manager.
	if err := registry.RegisterKeyManager(&stubKeysetDeriverKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name            string
		key             *stubKeysetDeriverKey
		wantKeysetHande *keyset.Handle
	}{
		{
			name: "TINK",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_TINK, 0x1234},
			wantKeysetHande: func() *keyset.Handle {
				ks := testutil.NewKeyset(0x1234, []*tinkpb.Keyset_Key{
					{
						KeyData: &tinkpb.KeyData{
							TypeUrl:         stubKeysetDeriverURL,
							Value:           []byte("a_very_unique_salt_derived_key"),
							KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
						},
						Status:           tinkpb.KeyStatusType_ENABLED,
						KeyId:            0x1234,
						OutputPrefixType: tinkpb.OutputPrefixType_TINK,
					},
				})
				kh, err := testkeyset.NewHandle(ks)
				if err != nil {
					t.Fatalf("testkeyset.NewHandle() err = %v, want nil", err)
				}
				return kh
			}(),
		},
		{
			name: "RAW",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_RAW, 0},
			wantKeysetHande: func() *keyset.Handle {
				ks := testutil.NewKeyset(0x12345678, []*tinkpb.Keyset_Key{
					{
						KeyData: &tinkpb.KeyData{
							TypeUrl:         stubKeysetDeriverURL,
							Value:           []byte("a_very_unique_salt_derived_key"),
							KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
						},
						Status:           tinkpb.KeyStatusType_ENABLED,
						KeyId:            0x12345678,
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
					},
				})
				kh, err := testkeyset.NewHandle(ks)
				if err != nil {
					t.Fatalf("testkeyset.NewHandle() err = %v, want nil", err)
				}
				return kh
			}(),
		},
		{
			name: "CRUNCHY",
			key:  &stubKeysetDeriverKey{tinkpb.OutputPrefixType_CRUNCHY, 0x1234},
			wantKeysetHande: func() *keyset.Handle {
				ks := testutil.NewKeyset(0x1234, []*tinkpb.Keyset_Key{
					{
						KeyData: &tinkpb.KeyData{
							TypeUrl:         stubKeysetDeriverURL,
							Value:           []byte("a_very_unique_salt_derived_key"),
							KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
						},
						Status:           tinkpb.KeyStatusType_ENABLED,
						KeyId:            0x1234,
						OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
					},
				})
				kh, err := testkeyset.NewHandle(ks)
				if err != nil {
					t.Fatalf("testkeyset.NewHandle() err = %v, want nil", err)
				}
				return kh
			}(),
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

			want := testkeyset.KeysetMaterial(tc.wantKeysetHande)
			gotHandle, err := keysetDeriver.DeriveKeyset([]byte("a_very_unique_salt"))
			if err != nil {
				t.Fatalf("keysetDeriver.DeriveKeyset() err = %v, want nil", err)
			}
			got := testkeyset.KeysetMaterial(gotHandle)

			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("keysetDeriver.DeriveKeyset() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
