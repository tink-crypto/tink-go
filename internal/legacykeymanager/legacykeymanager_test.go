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

package legacykeymanager

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	aesgcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	fakeKeyTypeURL = "type.googleapis.com/google.crypto.tink.FakeKey"
)

var (
	errFake = errors.New("fake error")
)

// fakeConfig is a fake implementation of the config interface.
type fakeConfig struct {
	primitive any
	err       error
}

func (c *fakeConfig) PrimitiveFromKey(k key.Key, _ internalapi.Token) (any, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.primitive, nil
}

func (c *fakeConfig) PrimitiveFromKeyData(keyData *tinkpb.KeyData, _ internalapi.Token) (any, error) {
	return nil, errors.New("unimplemented")
}

type fakeKey struct{}

var _ key.Key = (*fakeKey)(nil)

func (k *fakeKey) IDRequirement() (uint32, bool) { return 0, false }
func (k *fakeKey) Equal(other key.Key) bool      { return false }
func (k *fakeKey) Parameters() key.Parameters    { return &fakeParameters{} }

type fakeParameters struct {
	keyTypeURL string
}

func (p *fakeParameters) HasIDRequirement() bool          { return false }
func (p *fakeParameters) Equal(other key.Parameters) bool { return false }
func (p *fakeParameters) KeyType() string                 { return p.keyTypeURL }

func TestDoesSupport(t *testing.T) {
	for _, tc := range []struct {
		name    string
		km      registry.KeyManager
		typeURL string
		want    bool
	}{
		{
			name:    "KeyManager",
			km:      New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, nil),
			typeURL: fakeKeyTypeURL,
			want:    true,
		},
		{
			name:    "PrivateKeyManager",
			km:      NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, nil),
			typeURL: fakeKeyTypeURL,
			want:    true,
		},
		{
			name:    "KeyManager_invalidTypeURL",
			km:      New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, nil),
			typeURL: "invalid type URL",
			want:    false,
		},
		{
			name:    "PrivateKeyManager_invalidTypeURL",
			km:      NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, nil),
			typeURL: "invalid type URL",
			want:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.km.DoesSupport(tc.typeURL); got != tc.want {
				t.Errorf("DoesSupport(%q) = %v, want %v", tc.typeURL, got, tc.want)
			}
		})
	}
}

func TestTypeURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		km   registry.KeyManager
		want string
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, nil),
			want: fakeKeyTypeURL,
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, nil),
			want: fakeKeyTypeURL,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.km.TypeURL(); got != tc.want {
				t.Errorf("TypeURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPrimitive_Success(t *testing.T) {
	for _, tc := range []struct {
		name          string
		km            registry.KeyManager
		wantPrimitive any
	}{
		{
			name:          "KeyManager",
			km:            New(fakeKeyTypeURL, &fakeConfig{primitive: "primitive"}, tinkpb.KeyData_SYMMETRIC, nil),
			wantPrimitive: "primitive",
		},
		{
			name:          "PrivateKeyManager",
			km:            NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{primitive: "primitive"}, tinkpb.KeyData_SYMMETRIC, nil),
			wantPrimitive: "primitive",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey := random.GetRandomBytes(16)

			gotPrimitive, err := tc.km.Primitive(serializedKey)
			if err != nil {
				t.Fatalf("Primitive() err = %v, want nil", err)
			}
			if gotPrimitive != tc.wantPrimitive {
				t.Errorf("Primitive() = %v, want %v", gotPrimitive, tc.wantPrimitive)
			}
		})
	}
}

type fakeKeyParser struct {
	key key.Key
	err error
}

func (p *fakeKeyParser) ParseKey(keySerialization *protoserialization.KeySerialization) (key.Key, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.key, nil
}

type fakeKeySerializer struct {
	keyData *tinkpb.KeyData
	err     error
}

func (s *fakeKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	if s.err != nil {
		return nil, s.err
	}
	return protoserialization.NewKeySerialization(s.keyData, tinkpb.OutputPrefixType_RAW, 0)
}

type fakeParametersParser struct {
	params key.Parameters
	err    error
}

func (p *fakeParametersParser) Parse(keyTemplate *tinkpb.KeyTemplate) (key.Parameters, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.params, nil
}

func TestPrimitive_FailsIfConfigFails(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}
	for _, tc := range []struct {
		name string
		km   registry.KeyManager
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{err: errFake}, tinkpb.KeyData_SYMMETRIC, nil),
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{err: errFake}, tinkpb.KeyData_SYMMETRIC, nil),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.km.Primitive(random.GetRandomBytes(16)); !errors.Is(err, errFake) {
				t.Errorf("Primitive() err = %v, want %v", err, errFake)
			}
		})
	}
}

func TestNewKeyAndNewKeyData_Success(t *testing.T) {
	defer keygenregistry.UnregisterKeyCreator[*fakeParameters]()
	err := keygenregistry.RegisterKeyCreator[*fakeParameters](func(p key.Parameters, idRequirement uint32) (key.Key, error) {
		if _, ok := p.(*fakeParameters); !ok {
			return nil, fmt.Errorf("unexpected parameters: %v", p)
		}
		return &fakeKey{}, nil
	})
	if err != nil {
		t.Fatalf("keygenregistry.RegisterKeyCreator() err = %v", err)
	}
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()
	defer protoserialization.UnregisterParametersParser(fakeKeyTypeURL)

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{
		keyData: &tinkpb.KeyData{
			TypeUrl:         fakeKeyTypeURL,
			Value:           []byte("key format"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
		},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}
	if err := protoserialization.RegisterParametersParser(fakeKeyTypeURL, &fakeParametersParser{
		params: &fakeParameters{keyTypeURL: fakeKeyTypeURL},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}

	for _, tc := range []struct {
		name            string
		km              registry.KeyManager
		keyMaterialType tinkpb.KeyData_KeyMaterialType
		wantKey         proto.Message
	}{
		{
			name:            "KeyManager",
			km:              New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
			keyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			wantKey:         &aesgcmpb.AesGcmKey{},
		},
		{
			name:            "PrivateKeyManager",
			km:              NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
			keyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			wantKey:         &aesgcmpb.AesGcmKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NewKey", func(t *testing.T) {
				gotKey, err := tc.km.NewKey([]byte("key format"))
				if err != nil {
					t.Fatalf("NewKey() err = %v, want nil", err)
				}
				if !proto.Equal(gotKey, tc.wantKey) {
					t.Errorf("NewKey() = %v, want %v", gotKey, tc.wantKey)
				}
			})
			t.Run("NewKeyData", func(t *testing.T) {
				gotKeyData, err := tc.km.NewKeyData([]byte("key format"))
				if err != nil {
					t.Fatalf("NewKeyData() err = %v, want nil", err)
				}
				want := &tinkpb.KeyData{
					TypeUrl:         fakeKeyTypeURL,
					Value:           []byte("key format"),
					KeyMaterialType: tc.keyMaterialType,
				}
				if diff := cmp.Diff(want, gotKeyData, protocmp.Transform()); diff != "" {
					t.Errorf("NewKeyData() returned unexpected diff (-want +got):\n%s", diff)
				}
			})
		})
	}
}

func TestNewKeyAndNewKeyData_FailsIfNoParametersParserRegistered(t *testing.T) {
	defer keygenregistry.UnregisterKeyCreator[*fakeParameters]()
	err := keygenregistry.RegisterKeyCreator[*fakeParameters](func(p key.Parameters, idRequirement uint32) (key.Key, error) {
		if _, ok := p.(*fakeParameters); !ok {
			return nil, fmt.Errorf("unexpected parameters: %v", p)
		}
		return &fakeKey{}, nil
	})
	if err != nil {
		t.Fatalf("keygenregistry.RegisterKeyCreator() err = %v", err)
	}
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()

	for _, tc := range []struct {
		name string
		km   registry.KeyManager
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NewKey", func(t *testing.T) {
				if _, err := tc.km.NewKey([]byte("key format")); err == nil {
					t.Error("NewKey() err = nil, want error")
				}
			})
			t.Run("NewKeyData", func(t *testing.T) {
				if _, err := tc.km.NewKeyData([]byte("key format")); err == nil {
					t.Error("NewKeyData() err = nil, want error")
				}
			})
		})
	}
}

func TestNewKeyAndNewKeyData_FailsIfParametersParserFails(t *testing.T) {
	defer keygenregistry.UnregisterKeyCreator[*fakeParameters]()
	err := keygenregistry.RegisterKeyCreator[*fakeParameters](func(p key.Parameters, idRequirement uint32) (key.Key, error) {
		if _, ok := p.(*fakeParameters); !ok {
			return nil, fmt.Errorf("unexpected parameters: %v", p)
		}
		return &fakeKey{}, nil
	})
	if err != nil {
		t.Fatalf("keygenregistry.RegisterKeyCreator() err = %v", err)
	}
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()
	defer protoserialization.UnregisterParametersParser(fakeKeyTypeURL)

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{
		keyData: &tinkpb.KeyData{
			TypeUrl:         fakeKeyTypeURL,
			Value:           []byte("key format"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}
	if err := protoserialization.RegisterParametersParser(fakeKeyTypeURL, &fakeParametersParser{
		err: errFake, // Causes an error when parsing the parameters.
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}

	for _, tc := range []struct {
		name         string
		km           registry.KeyManager
		keyMashaller func([]byte) (proto.Message, error)
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NewKey", func(t *testing.T) {
				if _, err := tc.km.NewKey([]byte("key format")); !errors.Is(err, errFake) {
					t.Errorf("NewKey() err = %v, want %v", err, errFake)
				}
			})
			t.Run("NewKeyData", func(t *testing.T) {
				if _, err := tc.km.NewKeyData([]byte("key format")); !errors.Is(err, errFake) {
					t.Errorf("NewKeyData() err = %v, want %v", err, errFake)
				}
			})
		})
	}
}

func TestNewKeyAndNewKeyData_FailsIfNoKeyCreatorRegistered(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()
	defer protoserialization.UnregisterParametersParser(fakeKeyTypeURL)

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{
		keyData: &tinkpb.KeyData{
			TypeUrl:         fakeKeyTypeURL,
			Value:           []byte("key format"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}
	if err := protoserialization.RegisterParametersParser(fakeKeyTypeURL, &fakeParametersParser{
		params: &fakeParameters{keyTypeURL: fakeKeyTypeURL},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}

	for _, tc := range []struct {
		name string
		km   registry.KeyManager
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NewKey", func(t *testing.T) {
				if _, err := tc.km.NewKey([]byte("key format")); err == nil {
					t.Error("NewKey() err = nil, want error")
				}
			})
			t.Run("NewKeyData", func(t *testing.T) {
				if _, err := tc.km.NewKeyData([]byte("key format")); err == nil {
					t.Error("NewKeyData() err = nil, want error")
				}
			})
		})
	}
}

func TestNewKeyAndNewKeyData_FailsIfKeyCreatorFails(t *testing.T) {
	defer keygenregistry.UnregisterKeyCreator[*fakeParameters]()
	err := keygenregistry.RegisterKeyCreator[*fakeParameters](func(p key.Parameters, idRequirement uint32) (key.Key, error) {
		return nil, errFake // Causes an error when creating the key.
	})
	if err != nil {
		t.Fatalf("keygenregistry.RegisterKeyCreator() err = %v", err)
	}
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()
	defer protoserialization.UnregisterParametersParser(fakeKeyTypeURL)

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{
		keyData: &tinkpb.KeyData{
			TypeUrl:         fakeKeyTypeURL,
			Value:           []byte("key format"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}
	if err := protoserialization.RegisterParametersParser(fakeKeyTypeURL, &fakeParametersParser{
		params: &fakeParameters{keyTypeURL: fakeKeyTypeURL},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}

	for _, tc := range []struct {
		name string
		km   registry.KeyManager
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NewKey", func(t *testing.T) {
				if _, err := tc.km.NewKey([]byte("key format")); !errors.Is(err, errFake) {
					t.Errorf("NewKey() err = %v, want %v", err, errFake)
				}
			})
			t.Run("NewKeyData", func(t *testing.T) {
				if _, err := tc.km.NewKeyData([]byte("key format")); !errors.Is(err, errFake) {
					t.Errorf("NewKeyData() err = %v, want %v", err, errFake)
				}
			})
		})
	}
}

func TestNewKeyAndNewKeyData_FailsIfNoKeySerializerRegistered(t *testing.T) {
	defer keygenregistry.UnregisterKeyCreator[*fakeParameters]()
	err := keygenregistry.RegisterKeyCreator[*fakeParameters](func(p key.Parameters, idRequirement uint32) (key.Key, error) {
		if _, ok := p.(*fakeParameters); !ok {
			return nil, fmt.Errorf("unexpected parameters: %v", p)
		}
		return &fakeKey{}, nil
	})
	if err != nil {
		t.Fatalf("keygenregistry.RegisterKeyCreator() err = %v", err)
	}

	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterParametersParser(fakeKeyTypeURL)

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterParametersParser(fakeKeyTypeURL, &fakeParametersParser{
		params: &fakeParameters{keyTypeURL: fakeKeyTypeURL},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}

	for _, tc := range []struct {
		name string
		km   registry.KeyManager
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NewKey", func(t *testing.T) {
				if _, err := tc.km.NewKey([]byte("key format")); err == nil {
					t.Error("NewKey() err = nil, want error")
				}
			})
			t.Run("NewKeyData", func(t *testing.T) {
				if _, err := tc.km.NewKeyData([]byte("key format")); err == nil {
					t.Error("NewKeyData() err = nil, want error")
				}
			})
		})
	}
}

func TestNewKeyAndNewKeyData_FailsIfKeySerializerFails(t *testing.T) {
	defer keygenregistry.UnregisterKeyCreator[*fakeParameters]()
	err := keygenregistry.RegisterKeyCreator[*fakeParameters](func(p key.Parameters, idRequirement uint32) (key.Key, error) {
		if _, ok := p.(*fakeParameters); !ok {
			return nil, fmt.Errorf("unexpected parameters: %v", p)
		}
		return &fakeKey{}, nil
	})
	if err != nil {
		t.Fatalf("keygenregistry.RegisterKeyCreator() err = %v", err)
	}
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()
	defer protoserialization.UnregisterParametersParser(fakeKeyTypeURL)

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{
		err: errFake, // Causes an error when serializing the key.
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}
	if err := protoserialization.RegisterParametersParser(fakeKeyTypeURL, &fakeParametersParser{
		params: &fakeParameters{keyTypeURL: fakeKeyTypeURL},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}

	for _, tc := range []struct {
		name string
		km   registry.KeyManager
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil }),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NewKey", func(t *testing.T) {
				if _, err := tc.km.NewKey([]byte("key format")); !errors.Is(err, errFake) {
					t.Errorf("NewKey() err = %v, want %v", err, errFake)
				}
			})
			t.Run("NewKeyData", func(t *testing.T) {
				if _, err := tc.km.NewKeyData([]byte("key format")); !errors.Is(err, errFake) {
					t.Errorf("NewKeyData() err = %v, want %v", err, errFake)
				}
			})
		})
	}
}

func TestNewKey_FailsIfKeyMashallerFails(t *testing.T) {
	defer keygenregistry.UnregisterKeyCreator[*fakeParameters]()
	err := keygenregistry.RegisterKeyCreator[*fakeParameters](func(p key.Parameters, idRequirement uint32) (key.Key, error) {
		if _, ok := p.(*fakeParameters); !ok {
			return nil, fmt.Errorf("unexpected parameters: %v", p)
		}
		return &fakeKey{}, nil
	})
	if err != nil {
		t.Fatalf("keygenregistry.RegisterKeyCreator() err = %v", err)
	}
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()
	defer protoserialization.UnregisterParametersParser(fakeKeyTypeURL)

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{
		keyData: &tinkpb.KeyData{
			TypeUrl:         fakeKeyTypeURL,
			Value:           []byte("key format"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}
	if err := protoserialization.RegisterParametersParser(fakeKeyTypeURL, &fakeParametersParser{
		params: &fakeParameters{keyTypeURL: fakeKeyTypeURL},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}

	for _, tc := range []struct {
		name string
		km   registry.KeyManager
	}{
		{
			name: "KeyManager",
			km:   New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return nil, errFake }),
		},
		{
			name: "PrivateKeyManager",
			km:   NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) { return nil, errFake }),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NewKey", func(t *testing.T) {
				if _, err := tc.km.NewKey([]byte("key format")); !errors.Is(err, errFake) {
					t.Errorf("NewKey() err = %v, want %v", err, errFake)
				}
			})
			t.Run("NewKeyData", func(t *testing.T) {
				// Make sure NewKeyData doesn't fail.
				if _, err := tc.km.NewKeyData([]byte("key format")); err != nil {
					t.Errorf("NewKeyData() err = %v, want nil", err)
				}
			})
		})
	}
}

type fakePublicKey = fakeKey

type fakePrivateKey struct{}

var _ key.Key = (*fakePrivateKey)(nil)

func (k *fakePrivateKey) IDRequirement() (uint32, bool) { return 0, false }
func (k *fakePrivateKey) Equal(other key.Key) bool      { return false }
func (k *fakePrivateKey) Parameters() key.Parameters    { return &fakeParameters{} }
func (k *fakePrivateKey) PublicKey() (key.Key, error)   { return &fakePublicKey{}, nil }

func TestPublicKeyData_Success(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakePublicKey]()

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{key: &fakePrivateKey{}}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakePublicKey](&fakeKeySerializer{
		keyData: &tinkpb.KeyData{
			TypeUrl:         fakeKeyTypeURL,
			Value:           []byte("public key format"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}

	km := NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil })
	got, err := km.PublicKeyData([]byte("private key format"))
	if err != nil {
		t.Errorf("PublicKeyData() err = %v, want nil", err)
	}
	want := &tinkpb.KeyData{
		TypeUrl:         fakeKeyTypeURL,
		Value:           []byte("public key format"),
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("NewKeyData() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestPublicKeyData_FailsIfNoKeyParserRegistered(t *testing.T) {
	km := NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil })
	if _, err := km.PublicKeyData([]byte("private key format")); err == nil {
		t.Errorf("NewKeyData() err = nil, want error")
	}
}

func TestPublicKeyData_FailsIfKeyNotPrivateKey(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{key: &fakeKey{}}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{
		keyData: &tinkpb.KeyData{
			TypeUrl:         fakeKeyTypeURL,
			Value:           []byte("some key format"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}

	km := NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil })
	if _, err := km.PublicKeyData([]byte("private key format")); err == nil {
		t.Errorf("NewKeyData() err = nil, want error")
	}
}

func TestPublicKeyData_FailsIfNoPublicKeySerializerRegistered(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{key: &fakePrivateKey{}}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}

	km := NewPrivateKeyManager(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) { return &aesgcmpb.AesGcmKey{}, nil })
	if _, err := km.PublicKeyData([]byte("private key format")); err == nil {
		t.Errorf("NewKeyData() err = nil, want error")
	}
}
