// Copyright 2025 Google LLC
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

package primitiveregistry_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/key"
)

type testParameters struct {
	key.Parameters
	hasIDRequirement bool
}

func (p *testParameters) HasIDRequirement() bool {
	return p.hasIDRequirement
}

func (p *testParameters) Equal(other key.Parameters) bool {
	otherP, ok := other.(*testParameters)
	if !ok {
		return false
	}
	return p.hasIDRequirement == otherP.hasIDRequirement
}

type testKey struct {
	key.Key
	params *testParameters
	id     uint32
}

func (k *testKey) Parameters() key.Parameters {
	return k.params
}

func (k *testKey) IDRequirement() (uint32, bool) {
	if k.params.HasIDRequirement() {
		return k.id, true
	}
	return 0, false
}

func (k *testKey) Equal(other key.Key) bool {
	otherK, ok := other.(*testKey)
	if !ok {
		return false
	}
	return k.id == otherK.id && k.params.Equal(otherK.params)
}

type testPrimitive struct {
	ID uint32
}

type anotherTestKey struct {
	key.Key
}

func (k *anotherTestKey) Parameters() key.Parameters {
	return nil
}

func (k *anotherTestKey) IDRequirement() (uint32, bool) {
	return 0, false
}

func (k *anotherTestKey) Equal(other key.Key) bool {
	_, ok := other.(*anotherTestKey)
	return ok
}

func testPrimitiveConstructor(k key.Key) (any, error) {
	testK, ok := k.(*testKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type: %T", k)
	}
	id, _ := testK.IDRequirement()
	return &testPrimitive{ID: id}, nil
}

func TestRegisterPrimitiveConstructorAndPrimitive_Success(t *testing.T) {
	if err := primitiveregistry.RegisterPrimitiveConstructor[*testKey](testPrimitiveConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	defer primitiveregistry.UnregisterPrimitiveConstructor[*testKey]()
	k := &testKey{params: &testParameters{hasIDRequirement: true}, id: 123}
	p, err := primitiveregistry.Primitive(k)
	if err != nil {
		t.Fatalf("primitiveregistry.Primitive() err = %v, want nil", err)
	}
	testP, ok := p.(*testPrimitive)
	if !ok {
		t.Fatalf("primitive is not of type *testPrimitive")
	}
	if !cmp.Equal(testP, &testPrimitive{ID: 123}) {
		t.Errorf("primitiveregistry.Primitive() = %v, want %v", testP, &testPrimitive{ID: 123})
	}
}

func TestRegisterPrimitiveConstructor_SameConstructorTwiceIsNoOp(t *testing.T) {
	if err := primitiveregistry.RegisterPrimitiveConstructor[*testKey](testPrimitiveConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	defer primitiveregistry.UnregisterPrimitiveConstructor[*testKey]()
	if err := primitiveregistry.RegisterPrimitiveConstructor[*testKey](testPrimitiveConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
}

func TestRegisterPrimitiveConstructor_FailsIfDifferentConstructorRegistered(t *testing.T) {
	if err := primitiveregistry.RegisterPrimitiveConstructor[*testKey](testPrimitiveConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	defer primitiveregistry.UnregisterPrimitiveConstructor[*testKey]()
	anotherConstructor := func(k key.Key) (any, error) {
		return nil, nil
	}
	if err := primitiveregistry.RegisterPrimitiveConstructor[*testKey](anotherConstructor); err == nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = nil, want error")
	}
}

func TestPrimitive_Fails(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "anotherTestKey",
			key:  &anotherTestKey{},
		},
		{
			name: "nilKey",
			key:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := primitiveregistry.Primitive(tc.key); err == nil {
				t.Fatalf("primitiveregistry.Primitive() err = nil, want error")
			}
		})
	}
}

func TestUnregisterRemovesConstructor(t *testing.T) {
	if err := primitiveregistry.RegisterPrimitiveConstructor[*testKey](testPrimitiveConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	k := &testKey{params: &testParameters{hasIDRequirement: true}, id: 123}
	if _, err := primitiveregistry.Primitive(k); err != nil {
		t.Fatalf("primitiveregistry.Primitive() err = %v, want nil", err)
	}
	primitiveregistry.UnregisterPrimitiveConstructor[*testKey]()
	if _, err := primitiveregistry.Primitive(k); err == nil {
		t.Fatalf("primitiveregistry.Primitive() err = nil, want error")
	}
}
