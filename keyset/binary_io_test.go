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

package keyset_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestBinaryIOUnencrypted(t *testing.T) {
	buf := new(bytes.Buffer)
	w := keyset.NewBinaryWriter(buf)
	r := keyset.NewBinaryReader(buf)

	manager := testutil.NewHMACKeysetManager()
	h, err := manager.Handle()
	if h == nil || err != nil {
		t.Fatalf("cannot get keyset handle: %v", err)
	}

	ks1 := testkeyset.KeysetMaterial(h)
	if err := w.Write(ks1); err != nil {
		t.Fatalf("cannot write keyset: %v", err)
	}

	ks2, err := r.Read()
	if err != nil {
		t.Fatalf("cannot read keyset: %v", err)
	}

	if !proto.Equal(ks1, ks2) {
		t.Errorf("written keyset (%s) doesn't match read keyset (%s)", ks1, ks2)
	}
}

func TestBinaryIOEncrypted(t *testing.T) {
	buf := new(bytes.Buffer)
	w := keyset.NewBinaryWriter(buf)
	r := keyset.NewBinaryReader(buf)

	kse1 := &tinkpb.EncryptedKeyset{EncryptedKeyset: []byte(strings.Repeat("A", 32))}

	if err := w.WriteEncrypted(kse1); err != nil {
		t.Fatalf("cannot write encrypted keyset: %v", err)
	}

	kse2, err := r.ReadEncrypted()
	if err != nil {
		t.Fatalf("cannot read encrypted keyset: %v", err)
	}

	if !proto.Equal(kse1, kse2) {
		t.Errorf("written encrypted keyset (%s) doesn't match read encrypted keyset (%s)", kse1, kse2)
	}
}

func TestReadInBinaryWithTestVector(t *testing.T) {
	serializedKeysetEncryptionKeyset, err := hex.DecodeString("08cd9bdff30312540a480a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74696e6b2e41657347636d4b657912121a1082bbe6de4bf9a7655305615af46e594c1801100118cd9bdff3032001")
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}
	encryptedKeyset, err := hex.DecodeString("129101013e77cdcd28f57ffb418afa7f25d48a74efe720246e9aa538f33a702888bb7c48bce0e5a016a0c8e9085066d67c7c7fb40dceb176a3a10c7f7ab30c564dd8e2d918a2fc2d2e9a0245c537ff6d1fd756ff9d6de5cf4eb7f229de215e6e892f32fd703d0c9c3d2168813ad5bbc6ce108fcbfed0d9e3b14faae3e3789a891346d983b1ecca082f0546163351339aa142f574")
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}
	associatedData := []byte("associatedData")

	data := []byte("data")
	tag, err := hex.DecodeString("018f2d72de5055e622591fcf0fb85a7b4158e96f68")
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}

	keysetEncryptionHandle, err := testkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(serializedKeysetEncryptionKeyset)))
	if err != nil {
		t.Fatalf("testkeyset.Read() err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Fatalf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(encryptedKeyset)), keysetEncryptionAead, associatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithAssociatedData() err = %v, want nil", err)
	}
	primitive, err := mac.New(handle)
	if err != nil {
		t.Fatalf("mac.New(handle) err = %v, want nil", err)
	}
	if err := primitive.VerifyMAC(tag, data); err != nil {
		t.Fatalf("primitive.VerifyMAC(tag, data) err = %v, want nil", err)
	}
}

func TestBinaryWriteEncryptedOverhead(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Fatalf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}

	buf := &bytes.Buffer{}
	err = insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buf))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	serialized := buf.Bytes()
	rawEncryptedKeyset, err := keysetEncryptionAead.Encrypt(serialized, nil)
	if err != nil {
		t.Fatalf("keysetEncryptionAead.Encrypt() err = %v, want nil", err)
	}

	encBuf := &bytes.Buffer{}
	err = handle.Write(keyset.NewBinaryWriter(encBuf), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAead) err = %v, want nil", err)
	}
	encryptedKeyset := encBuf.Bytes()

	// encryptedKeyset is a serialized protocol buffer that contains only
	// rawEncryptedKeyset in a field. So
	// it should only be slightly larger than rawEncryptedKeyset.
	if len(encryptedKeyset) >= len(rawEncryptedKeyset)+6 {
		t.Errorf("len(encryptedKeyset) = %d, want < %d", len(encryptedKeyset), len(rawEncryptedKeyset)+6)
	}
}
