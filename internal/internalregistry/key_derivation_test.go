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

package internalregistry_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/testing/stubkeymanager"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	typeURLRoot           = "TestDeriveKeyFails"
	unregisteredKMTypeURL = typeURLRoot + "UnregisteredKeyManager"
	notDerivableKMTypeURL = typeURLRoot + "NotDerivableKeyManager"
	failingKMTypeURL      = typeURLRoot + "FailingKeyManager"
)

var once sync.Once

func mustRegisterBadKeyManagers(t *testing.T) {
	t.Helper()
	// The registry does not allow a key manager to be registered more than once.
	once.Do(func() {
		notDerivableKM := &stubkeymanager.StubKeyManager{URL: notDerivableKMTypeURL}
		if err := registry.RegisterKeyManager(notDerivableKM); err != nil {
			t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
		}

		failingKM := &stubkeymanager.StubDerivableKeyManager{
			StubKeyManager: stubkeymanager.StubKeyManager{
				URL: failingKMTypeURL,
			},
			DerErr: errors.New("failing"),
		}
		if err := registry.RegisterKeyManager(failingKM); err != nil {
			t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
		}
	})
}

func TestDerivableKeyManagers(t *testing.T) {
	mustRegisterBadKeyManagers(t)
	for _, typeURL := range []string{
		signature.ED25519KeyTemplate().GetTypeUrl(),
		failingKMTypeURL,
	} {
		t.Run(typeURL, func(t *testing.T) {
			if err := internalregistry.AllowKeyDerivation(typeURL); err != nil {
				t.Fatalf("internalregistry.AllowKeyDerivation() err = %v, want nil", err)
			}
			if !internalregistry.CanDeriveKeys(typeURL) {
				t.Errorf("internalregistry.CanDeriveKeys() = false, want true")
			}
		})
	}
}

func TestDerivableKeyManagersRejectsInvalidInputs(t *testing.T) {
	mustRegisterBadKeyManagers(t)
	for _, typeURL := range []string{
		"",
		unregisteredKMTypeURL,
		notDerivableKMTypeURL,
	} {
		t.Run(typeURL, func(t *testing.T) {
			if err := internalregistry.AllowKeyDerivation(typeURL); err == nil {
				t.Error("internalregistry.AllowKeyDerivation() err = nil, want non-nil")
			}
			if internalregistry.CanDeriveKeys(typeURL) {
				t.Errorf("internalregistry.CanDeriveKeys() = true, want false")
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	for _, test := range []struct {
		name            string
		keyTemplate     *tinkpb.KeyTemplate
		keySize         uint32
		keyMaterialType tinkpb.KeyData_KeyMaterialType
	}{
		{
			name:            "HMAC-SHA256-Tag128",
			keyTemplate:     mac.HMACSHA256Tag128KeyTemplate(),
			keySize:         32,
			keyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		{
			name:            "HMAC-SHA256-Tag256",
			keyTemplate:     mac.HMACSHA256Tag256KeyTemplate(),
			keySize:         32,
			keyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := bytes.NewBuffer(random.GetRandomBytes(test.keySize))
			keyData, err := internalregistry.DeriveKey(test.keyTemplate, buf)
			if err != nil {
				t.Fatalf("internalregistry.DeriveKey() err = %v, want nil", err)
			}
			if got, want := keyData.GetTypeUrl(), test.keyTemplate.GetTypeUrl(); got != want {
				t.Errorf("TypeUrl = %s, want %s", got, want)
			}
			key := &gcmpb.AesGcmKey{}
			if err := proto.Unmarshal(keyData.GetValue(), key); err != nil {
				t.Errorf("proto.Unmarshal() err = %v, want nil", err)
			}
			if got, want := len(key.GetKeyValue()), int(test.keySize); got != want {
				t.Errorf("len(KeyValue) = %d, want %d", got, want)
			}
			if got, want := keyData.GetKeyMaterialType(), test.keyMaterialType; got != want {
				t.Errorf("KeyMaterialType = %s, want %s", got, want)
			}
		})
	}
}

func TestDeriveKeyFails(t *testing.T) {
	mustRegisterBadKeyManagers(t)
	rand := random.GetRandomBytes(32)
	for _, test := range []struct {
		name        string
		keyTemplate *tinkpb.KeyTemplate
		randLen     uint32
	}{
		{
			name:        "not enough randomness",
			keyTemplate: mac.HMACSHA256Tag128KeyTemplate(),
			randLen:     15},
		{
			name:    "nil key template",
			randLen: 32},
		{
			name:        "derivation-disallowed but registered key manager",
			keyTemplate: aead.AES128CTRHMACSHA256KeyTemplate(),
			randLen:     32,
		},
		{
			name: "derivation-allowed but unregistered key manager",
			keyTemplate: &tinkpb.KeyTemplate{
				TypeUrl:          unregisteredKMTypeURL,
				Value:            rand,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
			randLen: 32,
		},
		{
			"does not implement DerivableKeyManager",
			&tinkpb.KeyTemplate{
				TypeUrl:          notDerivableKMTypeURL,
				Value:            rand,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
			32,
		},
		{
			"key manager with failing DeriveKey()",
			&tinkpb.KeyTemplate{
				TypeUrl:          failingKMTypeURL,
				Value:            rand,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
			},
			32,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := bytes.NewBuffer(random.GetRandomBytes(test.randLen))
			if _, err := internalregistry.DeriveKey(test.keyTemplate, buf); err == nil {
				t.Error("internalregistry.DeriveKey() err = nil, want non-nil")
			}
		})
	}
}
