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

package insecurecleartextkeyset_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// A KeysetReader that always returns nil.
type NilKeysetReader struct {
}

func (m *NilKeysetReader) Read() (*tinkpb.Keyset, error) {
	return nil, nil
}

func (m *NilKeysetReader) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	return nil, nil
}

func mustCreateTestKeysetHandle(t *testing.T) *keyset.Handle {
	t.Helper()
	km := keyset.NewManager()
	p, err := keytest.NewParameters(keytest.VariantTink)
	if err != nil {
		t.Fatalf("keytest.NewParameters(keytest.VariantTink) err = %v, want nil", err)
	}
	keyID, err := km.AddNewKeyFromParameters(p)
	if err != nil {
		t.Fatalf("km.AddNewKeyFromParameters(%v) err = %v, want nil", p, err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary(%d) err = %v, want nil", keyID, err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	return handle
}

func TestReadWithNilKeysetFails(t *testing.T) {
	if _, err := insecurecleartextkeyset.Read(&NilKeysetReader{}); err == nil {
		t.Error("insecurecleartextkeyset.Read(&NilKeysetReader{}) err = nil, want error")
	}
}

func TestReadWithNilReaderFails(t *testing.T) {
	if _, err := insecurecleartextkeyset.Read(nil); err == nil {
		t.Error("insecurecleartextkeyset.Read(nil) err = nil, want error")
	}
}

func TestWriteWithNilHandleFails(t *testing.T) {
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(nil, keyset.NewBinaryWriter(buff)); err == nil {
		t.Error("insecurecleartextkeyset.Write(nil, _) err = nil, want error")
	}
}

func TestWriteWithNilWriterFails(t *testing.T) {
	handle := mustCreateTestKeysetHandle(t)
	if err := insecurecleartextkeyset.Write(handle, nil); err == nil {
		t.Error("insecurecleartextkeyset.Write(_, nil) err = nil, want error")
	}
}

func TestWriteAndReadInBinary(t *testing.T) {
	handle := mustCreateTestKeysetHandle(t)
	buff := &bytes.Buffer{}
	err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	serialized := buff.Bytes()

	parsedHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}

	want := insecurecleartextkeyset.KeysetMaterial(handle)
	got := insecurecleartextkeyset.KeysetMaterial(parsedHandle)
	if !proto.Equal(got, want) {
		t.Errorf("KeysetMaterial(Read()) = %q, want %q", got, want)
	}
}

func TestWriteAndReadInJson(t *testing.T) {
	handle := mustCreateTestKeysetHandle(t)

	buff := &bytes.Buffer{}
	err := insecurecleartextkeyset.Write(handle, keyset.NewJSONWriter(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	serialized := buff.Bytes()

	parsedHandle, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewBuffer(serialized)))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}

	want := insecurecleartextkeyset.KeysetMaterial(handle)
	got := insecurecleartextkeyset.KeysetMaterial(parsedHandle)
	if !proto.Equal(got, want) {
		t.Errorf("KeysetMaterial(Read()) = %q, want %q", got, want)
	}
}

func TestLegacyKeysetHandle(t *testing.T) {
	handle := mustCreateTestKeysetHandle(t)
	ks := insecurecleartextkeyset.KeysetMaterial(handle)
	gotHandle1 := insecurecleartextkeyset.KeysetHandle(ks)
	if !cmp.Equal(gotHandle1.KeysetInfo(), handle.KeysetInfo(), protocmp.Transform()) {
		t.Errorf("gotHandle1.KeysetInfo() = %v, want %v", gotHandle1.KeysetInfo(), handle.KeysetInfo())
	}
	serializedKeyset, err := proto.Marshal(ks)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	gotHandle2, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset)))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	if !cmp.Equal(gotHandle2.KeysetInfo(), handle.KeysetInfo(), protocmp.Transform()) {
		t.Errorf("gotHandle2.KeysetInfo() = %v, want %v", gotHandle2.KeysetInfo(), handle.KeysetInfo())
	}
}

func TestLegacyKeysetHandleWithNilKeysetReturnsNil(t *testing.T) {
	handle := insecurecleartextkeyset.KeysetHandle(nil)
	if handle != nil {
		t.Error("insecurecleartextkeyset.KeysetHandle(nil) != nil, want nil")
	}
}

func TestHandleFromReaderWithAnnotationsGetsMonitored(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle := mustCreateTestKeysetHandle(t)
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	wantAnnotations := map[string]string{"foo": "bar"}
	annotatedHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(wantAnnotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	primary, err := annotatedHandle.Primary()
	if err != nil {
		t.Fatalf("annotatedHandle.Primary() err = %v, want nil", err)
	}
	factory, err := factoryutil.NewLoggerFactory(annotatedHandle)
	if err != nil {
		t.Fatalf("factoryutil.NewLoggerFactory() err = %v, want nil", err)
	}
	logger, err := factory.CreateFor("test_primitive", "test_function")
	if err != nil {
		t.Fatalf("factory.CreateFor() err = %v, want nil", err)
	}
	logger.Log(primary.KeyID(), len("some_data"))
	events := client.Events()
	if len(events) != 1 {
		t.Fatalf("len(client.Events()) = %d, want 1", len(events))
	}
	gotAnnotations := events[0].Context.KeysetInfo.Annotations
	if !cmp.Equal(gotAnnotations, wantAnnotations) {
		t.Errorf("Annotations = %v, want %v", gotAnnotations, wantAnnotations)
	}
}

func TestHandleFromReaderWithAnnotationsTwiceFails(t *testing.T) {
	handle := mustCreateTestKeysetHandle(t)
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	if _, err := insecurecleartextkeyset.Read(
		keyset.NewBinaryReader(buff),
		keyset.WithAnnotations(annotations),
		keyset.WithAnnotations(annotations)); err == nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = nil, want error")
	}
}

func TestHandleFromReaderWithoutAnnotationsDoesNotGetMonitored(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle := mustCreateTestKeysetHandle(t)
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	unannotatedHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	primary, err := unannotatedHandle.Primary()
	if err != nil {
		t.Fatalf("unannotatedHandle.Primary() err = %v, want nil", err)
	}
	factory, err := factoryutil.NewLoggerFactory(unannotatedHandle)
	if err != nil {
		t.Fatalf("factoryutil.NewLoggerFactory() err = %v, want nil", err)
	}
	logger, err := factory.CreateFor("test_primitive", "test_function")
	if err != nil {
		t.Fatalf("factory.CreateFor() err = %v, want nil", err)
	}
	logger.Log(primary.KeyID(), len("some_data"))
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
}
