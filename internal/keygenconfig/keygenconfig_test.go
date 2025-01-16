// Copyright 2024 Google LLC
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

package keygenconfig_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/keygenconfig"
	"github.com/tink-crypto/tink-go/v2/key"
)

type stubParams1 struct{}

func (p *stubParams1) HasIDRequirement() bool          { return true }
func (p *stubParams1) Equal(other key.Parameters) bool { return true }

type stubKey1 struct{}

func (k *stubKey1) Parameters() key.Parameters    { return &stubParams1{} }
func (k *stubKey1) Equal(other key.Key) bool      { return true }
func (k *stubKey1) IDRequirement() (uint32, bool) { return 123, true }

func stubKeyCreator1(p key.Parameters, idRequirement uint32) (key.Key, error) {
	return &stubKey1{}, nil
}

type stubParams2 struct{}

func (p *stubParams2) HasIDRequirement() bool          { return false }
func (p *stubParams2) Equal(other key.Parameters) bool { return true }

type stubKey2 struct{}

func (k *stubKey2) Parameters() key.Parameters    { return nil }
func (k *stubKey2) Equal(other key.Key) bool      { return true }
func (k *stubKey2) IDRequirement() (uint32, bool) { return 123, true }

func stubKeyCreator2(p key.Parameters, idRequirement uint32) (key.Key, error) {
	return &stubKey2{}, nil
}

func TestRegisterKeyCreatorWorks(t *testing.T) {
	config := keygenconfig.New()
	if err := config.RegisterKeyCreator(reflect.TypeOf((*stubParams1)(nil)), stubKeyCreator1); err != nil {
		t.Fatalf("config.RegisterKeyCreator(reflect.TypeOf((*stubParams1)(nil)), stubKeyCreator1) err = %v, want nil", err)
	}
	if err := config.RegisterKeyCreator(reflect.TypeOf((*stubParams2)(nil)), stubKeyCreator2); err != nil {
		t.Fatalf("config.RegisterKeyCreator(reflect.TypeOf((*stubParams2)(nil)), stubKeyCreator2) err = %v, want nil", err)
	}
	key1, err := config.CreateKey(&stubParams1{}, 123)
	if err != nil {
		t.Fatalf("config.CreateKey(&stubParams1{}, 123) err = %v, want nil", err)
	}
	if _, ok := key1.(*stubKey1); !ok {
		t.Errorf("key is of type %T; want *stubKey1", key1)
	}
	key2, err := config.CreateKey(&stubParams2{}, 123)
	if err != nil {
		t.Fatalf("config.CreateKey(&stubParams2{}, 123) err = %v, want nil", err)
	}
	if _, ok := key2.(*stubKey2); !ok {
		t.Errorf("key is of type %T; want *stubKey2", key2)
	}
}

func TestRegisterKeyCreatorFailsIfRegisteredTwice(t *testing.T) {
	config := keygenconfig.New()
	if err := config.RegisterKeyCreator(reflect.TypeOf((*stubParams1)(nil)), stubKeyCreator1); err != nil {
		t.Errorf("config.RegisterKeyCreator(reflect.TypeOf((*stubParams1)(nil)), stubKeyCreator1) err = %v, want nil", err)
	}
	// Another creator function for the same type fails.
	if err := config.RegisterKeyCreator(reflect.TypeOf((*stubParams1)(nil)), stubKeyCreator2); err == nil {
		t.Errorf("config.RegisterKeyCreator(reflect.TypeOf((*stubParams1)(nil)), stubKeyCreator1) err = nil, want error")
	}
}

func TestCreateKeyFailsIfKeyCreatorIsNotRegistered(t *testing.T) {
	config := keygenconfig.New()
	if _, err := config.CreateKey(&stubParams1{}, 123); err == nil {
		t.Errorf("config.CreateKey(&stubParams1{}, 123) err = nil, want error")
	}
}

func stubKeyCreatorFails(p key.Parameters, idRequirement uint32) (key.Key, error) {
	return nil, errors.New("oh no :(")
}

func TestCreateKeyFailsIfKeyCreatorFails(t *testing.T) {
	config := keygenconfig.New()
	if err := config.RegisterKeyCreator(reflect.TypeOf((*stubParams1)(nil)), stubKeyCreatorFails); err != nil {
		t.Errorf("config.RegisterKeyCreator(reflect.TypeOf((*stubParams1)(nil)), stubKeyCreatorFails) err = %v, want nil", err)
	}
	if _, err := config.CreateKey(&stubParams1{}, 123); err == nil {
		t.Errorf("config.CreateKey(&stubParams1{}, 123) err = nil, want error")
	}
}
