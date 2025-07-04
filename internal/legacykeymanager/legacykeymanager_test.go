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
	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, nil)
	if !km.DoesSupport(fakeKeyTypeURL) {
		t.Errorf("DoesSupport(%q) = false, want true", fakeKeyTypeURL)
	}
	if km.DoesSupport("some other type url") {
		t.Error("DoesSupport(\"some other type url\") = true, want false")
	}
}

func TestTypeURL(t *testing.T) {
	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, nil)
	if got, want := km.TypeURL(), fakeKeyTypeURL; got != want {
		t.Errorf("TypeURL() = %q, want %q", got, want)
	}
}

func TestPrimitive_Success(t *testing.T) {
	wantPrimitive := "primitive"
	km := New(fakeKeyTypeURL, &fakeConfig{primitive: wantPrimitive}, tinkpb.KeyData_SYMMETRIC, nil)

	serializedKey := random.GetRandomBytes(16)

	gotPrimitive, err := km.Primitive(serializedKey)
	if err != nil {
		t.Fatalf("Primitive() err = %v, want nil", err)
	}
	if gotPrimitive != wantPrimitive {
		t.Errorf("Primitive() = %v, want %v", gotPrimitive, wantPrimitive)
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
	km := New(fakeKeyTypeURL, &fakeConfig{err: errFake}, tinkpb.KeyData_SYMMETRIC, nil)

	defer protoserialization.UnregisterKeyParser(fakeKeyTypeURL)
	defer protoserialization.UnregisterKeySerializer[*fakeKey]()

	if err := protoserialization.RegisterKeyParser(fakeKeyTypeURL, &fakeKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v", err)
	}
	if err := protoserialization.RegisterKeySerializer[*fakeKey](&fakeKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v", err)
	}
	if _, err := km.Primitive(random.GetRandomBytes(16)); !errors.Is(err, errFake) {
		t.Errorf("Primitive() err = %v, want %v", err, errFake)
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

	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_ASYMMETRIC_PRIVATE, func([]byte) (proto.Message, error) {
		return &aesgcmpb.AesGcmKey{}, nil
	})

	t.Run("NewKey", func(t *testing.T) {
		gotKey, err := km.NewKey([]byte("key format"))
		if err != nil {
			t.Fatalf("NewKey() err = %v, want nil", err)
		}
		if !proto.Equal(gotKey, &aesgcmpb.AesGcmKey{}) {
			t.Errorf("NewKey() = %v, want %v", gotKey, &aesgcmpb.AesGcmKey{})
		}
	})
	t.Run("NewKeyData", func(t *testing.T) {
		gotKeyData, err := km.NewKeyData([]byte("key format"))
		if err != nil {
			t.Fatalf("NewKeyData() err = %v, want nil", err)
		}
		want := &tinkpb.KeyData{
			TypeUrl:         fakeKeyTypeURL,
			Value:           []byte("key format"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
		}
		if diff := cmp.Diff(want, gotKeyData, protocmp.Transform()); diff != "" {
			t.Errorf("NewKeyData() returned unexpected diff (-want +got):\n%s", diff)
		}
	})
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

	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) {
		return &aesgcmpb.AesGcmKey{}, nil
	})
	t.Run("NewKey", func(t *testing.T) {
		if _, err := km.NewKey([]byte("key format")); err == nil {
			t.Error("NewKey() err = nil, want error")
		}
	})
	t.Run("NewKeyData", func(t *testing.T) {
		if _, err := km.NewKeyData([]byte("key format")); err == nil {
			t.Error("NewKeyData() err = nil, want error")
		}
	})
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

	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) {
		return &aesgcmpb.AesGcmKey{}, nil
	})
	t.Run("NewKey", func(t *testing.T) {
		if _, err := km.NewKey([]byte("key format")); !errors.Is(err, errFake) {
			t.Errorf("NewKey() err = %v, want %v", err, errFake)
		}
	})
	t.Run("NewKeyData", func(t *testing.T) {
		if _, err := km.NewKeyData([]byte("key format")); !errors.Is(err, errFake) {
			t.Errorf("NewKeyData() err = %v, want %v", err, errFake)
		}
	})
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

	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) {
		return &aesgcmpb.AesGcmKey{}, nil
	})

	t.Run("NewKey", func(t *testing.T) {
		if _, err := km.NewKey([]byte("key format")); err == nil {
			t.Error("NewKey() err = nil, want error")
		}
	})
	t.Run("NewKeyData", func(t *testing.T) {
		if _, err := km.NewKeyData([]byte("key format")); err == nil {
			t.Error("NewKeyData() err = nil, want error")
		}
	})
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

	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) {
		return &aesgcmpb.AesGcmKey{}, nil
	})

	t.Run("NewKey", func(t *testing.T) {
		if _, err := km.NewKey([]byte("key format")); !errors.Is(err, errFake) {
			t.Errorf("NewKey() err = %v, want %v", err, errFake)
		}
	})
	t.Run("NewKeyData", func(t *testing.T) {
		if _, err := km.NewKeyData([]byte("key format")); !errors.Is(err, errFake) {
			t.Errorf("NewKeyData() err = %v, want %v", err, errFake)
		}
	})
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

	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) {
		return &aesgcmpb.AesGcmKey{}, nil
	})

	t.Run("NewKey", func(t *testing.T) {
		if _, err := km.NewKey([]byte("key format")); err == nil {
			t.Error("NewKey() err = nil, want error")
		}
	})
	t.Run("NewKeyData", func(t *testing.T) {
		if _, err := km.NewKeyData([]byte("key format")); err == nil {
			t.Error("NewKeyData() err = nil, want error")
		}
	})
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

	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) {
		return &aesgcmpb.AesGcmKey{}, nil
	})

	t.Run("NewKey", func(t *testing.T) {
		if _, err := km.NewKey([]byte("key format")); !errors.Is(err, errFake) {
			t.Errorf("NewKey() err = %v, want %v", err, errFake)
		}
	})
	t.Run("NewKeyData", func(t *testing.T) {
		if _, err := km.NewKeyData([]byte("key format")); !errors.Is(err, errFake) {
			t.Errorf("NewKeyData() err = %v, want %v", err, errFake)
		}
	})
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

	km := New(fakeKeyTypeURL, &fakeConfig{}, tinkpb.KeyData_SYMMETRIC, func([]byte) (proto.Message, error) {
		return nil, errFake // Causes an error when unmarshalling the key.
	})

	if _, err := km.NewKey([]byte("key format")); !errors.Is(err, errFake) {
		t.Errorf("NewKey() err = %v, want %v", err, errFake)
	}

	// Make sure NewKeyData doesn't fail.
	if _, err := km.NewKeyData([]byte("key format")); err != nil {
		t.Errorf("NewKeyData() err = %v, want nil", err)
	}
}
