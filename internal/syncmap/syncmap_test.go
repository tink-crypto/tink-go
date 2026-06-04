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

package syncmap_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/syncmap"
)

func TestMapLoadOrStore(t *testing.T) {
	m := &syncmap.Map[string, int]{}

	val, loaded := m.LoadOrStore("key", 1)
	if loaded {
		t.Errorf("m.LoadOrStore(\"key\", 1) = %v, %v, want _, false", val, loaded)
	}
	if val != 1 {
		t.Errorf("m.LoadOrStore(\"key\", 1) = %v, _, want 1, _", val)
	}

	val, loaded = m.LoadOrStore("key", 2)
	if !loaded {
		t.Errorf("m.LoadOrStore(\"key\", 2) = %v, %v, want _, true", val, loaded)
	}
	if val != 1 {
		t.Errorf("m.LoadOrStore(\"key\", 2) = %v, _, want 1, _", val)
	}
}

func TestMapLoad(t *testing.T) {
	m := &syncmap.Map[string, int]{}

	val, ok := m.Load("missing")
	if ok {
		t.Errorf("m.Load(\"missing\") = %v, %v, want _, false", val, ok)
	}
	if val != 0 {
		t.Errorf("m.Load(\"missing\") = %v, _, want 0, _", val)
	}

	m.LoadOrStore("key", 42)
	val, ok = m.Load("key")
	if !ok {
		t.Errorf("m.Load(\"key\") = %v, %v, want _, true", val, ok)
	}
	if val != 42 {
		t.Errorf("m.Load(\"key\") = %v, _, want 42, _", val)
	}
}

func TestMapDelete(t *testing.T) {
	m := &syncmap.Map[string, int]{}

	m.LoadOrStore("key", 42)
	m.Delete("key")

	val, ok := m.Load("key")
	if ok {
		t.Errorf("m.Load(\"key\") after Delete = %v, %v, want _, false", val, ok)
	}
}

func TestMapClear(t *testing.T) {
	m := &syncmap.Map[string, int]{}

	m.LoadOrStore("key1", 1)
	m.LoadOrStore("key2", 2)

	m.Clear()

	if _, ok := m.Load("key1"); ok {
		t.Errorf("m.Load(\"key1\") after Clear returned true")
	}
	if _, ok := m.Load("key2"); ok {
		t.Errorf("m.Load(\"key2\") after Clear returned true")
	}
}
