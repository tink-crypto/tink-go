// Copyright 2018 Google LLC
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

package signature_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/internal/testing/stubkeymanager"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestSignerVerifyFactory(t *testing.T) {
	tinkPriv, tinkPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	legacyPriv, legacyPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		tinkpb.OutputPrefixType_LEGACY,
		2)
	rawPriv, rawPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		tinkpb.OutputPrefixType_RAW,
		3)
	crunchyPriv, crunchyPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		tinkpb.OutputPrefixType_CRUNCHY,
		4)
	privKeys := []*tinkpb.Keyset_Key{tinkPriv, legacyPriv, rawPriv, crunchyPriv}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	privKeysetHandle, err := testkeyset.NewHandle(privKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %q, want nil", err)
	}
	pubKeys := []*tinkpb.Keyset_Key{tinkPub, legacyPub, rawPub, crunchyPub}
	pubKeyset := testutil.NewKeyset(pubKeys[0].KeyId, pubKeys)
	pubKeysetHandle, err := testkeyset.NewHandle(pubKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(pubKeyset) err = %v, want nil", err)
	}
	// sign some random data
	signer, err := signature.NewSigner(privKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privKeysetHandle) err = %v, want nil", err)
	}
	data := random.GetRandomBytes(1211)
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign(data) err = %v, want nil", err)
	}
	// verify with the same set of public keys should work
	verifier, err := signature.NewVerifier(pubKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(pubKeysetHandle) err = %v, want nil", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Errorf("verifier.Verify(sig, data) = %v, want nil", err)
	}
	// verify with other key should fail
	_, otherPub := newECDSAKeysetKeypair(t, commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		tinkpb.OutputPrefixType_TINK,
		1)
	otherPubKeys := []*tinkpb.Keyset_Key{otherPub}
	otherPubKeyset := testutil.NewKeyset(otherPubKeys[0].KeyId, otherPubKeys)
	otherPubKeysetHandle, err := testkeyset.NewHandle(otherPubKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(otherPubKeyset) err = %v, want nil", err)
	}
	otherVerifier, err := signature.NewVerifier(otherPubKeysetHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(otherPubKeysetHandle) err = %v, want nil", err)
	}
	if err = otherVerifier.Verify(sig, data); err == nil {
		t.Error("otherVerifier.Verify(sig, data) = nil, want not nil")
	}
}

func TestPrimitiveFactoryFailsWithEmptyHandle(t *testing.T) {
	handle := &keyset.Handle{}
	if _, err := signature.NewVerifier(handle); err == nil {
		t.Errorf("signature.NewVerifier(handle) err = nil, want not nil")
	}
}

func newECDSAKeysetKeypair(t *testing.T, hashType commonpb.HashType, curve commonpb.EllipticCurveType, outputPrefixType tinkpb.OutputPrefixType, keyID uint32) (*tinkpb.Keyset_Key, *tinkpb.Keyset_Key) {
	t.Helper()
	key := testutil.NewRandomECDSAPrivateKey(hashType, curve)
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	keyData := testutil.NewKeyData(testutil.ECDSASignerTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	privKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)

	serializedKey, err = proto.Marshal(key.PublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	keyData = testutil.NewKeyData(testutil.ECDSAVerifierTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	pubKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)
	return privKey, pubKey
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}

	_, err = signature.NewSigner(wrongKH)
	if err == nil {
		t.Error("signature.NewSigner(wrongKH) err = nil, want not nil")
	}

	_, err = signature.NewVerifier(wrongKH)
	if err == nil {
		t.Error("signature.NewVerifier(wrongKH) err = nil, want not nil")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}

	_, err = signature.NewSigner(goodKH)
	if err != nil {
		t.Fatalf("signature.NewSigner(goodKH) err = %v, want nil", err)
	}

	goodPublicKH, err := goodKH.Public()
	if err != nil {
		t.Fatalf("goodKH.Public() err = %v, want nil", err)
	}

	_, err = signature.NewVerifier(goodPublicKH)
	if err != nil {
		t.Errorf("signature.NewVerifier(goodPublicKH) err = %v, want nil", err)
	}
}

func TestPrimitiveFactorySignVerifyWithoutAnnotationsDoesNothing(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier() err = %v, want nil", err)
	}
	data := []byte("some_important_data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Fatalf("verifier.Verify() err = %v, want nil", err)
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsLogSignVerify(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier() err = %v, want nil", err)
	}
	data := []byte("some_important_data")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	if err := verifier.Verify(sig, data); err != nil {
		t.Fatalf("verifier.Verify() err = %v, want nil", err)
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
	got := client.Events()
	wantVerifyKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: pubHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.Ed25519PublicKey",
				KeyPrefix: "TINK",
			},
		},
	}
	wantSignKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.Ed25519PrivateKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("public_key_sign", "sign", wantSignKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("public_key_verify", "verify", wantVerifyKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

type alwaysFailingSigner struct{}

func (a *alwaysFailingSigner) Sign(data []byte) ([]byte, error) { return nil, fmt.Errorf("failed") }

func TestPrimitiveFactoryMonitoringWithAnnotationsSignFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	typeURL := "TestPrimitiveFactoryMonitoringWithAnnotationsSignFailureIsLogged" + "PrivateKeyManager"
	km := &stubkeymanager.StubPrivateKeyManager{
		StubKeyManager: stubkeymanager.StubKeyManager{
			URL:  typeURL,
			Prim: &alwaysFailingSigner{},
			KeyData: &tinkpb.KeyData{
				TypeUrl:         typeURL,
				Value:           []byte("serialized_key"),
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			},
		},
	}
	if err := registry.RegisterKeyManager(km); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}
	template := &tinkpb.KeyTemplate{
		TypeUrl:          typeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_LEGACY,
	}
	kh, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner() err = %v, want nil", err)
	}
	if _, err := signer.Sign([]byte("some_data")); err == nil {
		t.Fatalf("signer.Sign() err = nil, want error")
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"public_key_sign",
				"sign",
				monitoring.NewKeysetInfo(
					annotations,
					kh.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   typeURL,
							KeyPrefix: "LEGACY",
						},
					},
				),
			),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsVerifyFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	annotations := map[string]string{"foo": "bar"}
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier() err = %v, want nil", err)
	}
	if err := verifier.Verify([]byte("some_invalid_signature"), []byte("some_invalid_data")); err == nil {
		t.Fatalf("verifier.Verify() err = nil, want error")
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"public_key_verify",
				"verify",
				monitoring.NewKeysetInfo(
					annotations,
					pubHandle.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.Ed25519PublicKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestVerifyWithLegacyKeyDoesNotHaveSideEffectOnMessage(t *testing.T) {
	privateKey, publicKey := newECDSAKeysetKeypair(t, commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		tinkpb.OutputPrefixType_LEGACY,
		2)
	privateKeyset := testutil.NewKeyset(privateKey.KeyId, []*tinkpb.Keyset_Key{privateKey})
	privateHandle, err := testkeyset.NewHandle(privateKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(privateHandle) err = %v, want nil", err)
	}
	publicKeyset := testutil.NewKeyset(publicKey.KeyId, []*tinkpb.Keyset_Key{publicKey})
	publicHandle, err := testkeyset.NewHandle(publicKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(publicKeyset) err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("signature.NewSigner(privateHandle) err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(publicHandle) err = %v, want nil", err)
	}

	data := []byte("data")
	message := data[:3] // Let message be a slice of data.

	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign(message) err = %v, want nil", err)
	}
	err = verifier.Verify(sig, message)
	if err != nil {
		t.Fatalf("verifier.Verify(sig, message) err = %v, want nil", err)
	}
	wantData := []byte("data")
	if !bytes.Equal(data, wantData) {
		t.Errorf("data = %q, want: %q", data, wantData)
	}
}

const stubKeyURL = "type.googleapis.com/google.crypto.tink.SomeKey"

type stubFullSigner struct{}

func (s *stubFullSigner) Sign(data []byte) ([]byte, error) {
	return slices.Concat([]byte("full_signer_prefix"), data), nil
}

type stubParams struct{}

var _ key.Parameters = (*stubParams)(nil)

func (p *stubParams) Equals(_ key.Parameters) bool { return true }
func (p *stubParams) HasIDRequirement() bool       { return true }

type stubPublicKey struct{}

var _ key.Key = (*stubPublicKey)(nil)

func (p *stubPublicKey) Equals(_ key.Key) bool         { return true }
func (p *stubPublicKey) Parameters() key.Parameters    { return &stubParams{} }
func (p *stubPublicKey) IDRequirement() (uint32, bool) { return 0, false }
func (p *stubPublicKey) HasIDRequirement() bool        { return true }

type stubPrivateKey struct {
	prefixType   tinkpb.OutputPrefixType
	idRequrement uint32
}

var _ key.Key = (*stubPrivateKey)(nil)

func (p *stubPrivateKey) Equals(_ key.Key) bool         { return true }
func (p *stubPrivateKey) Parameters() key.Parameters    { return &stubParams{} }
func (p *stubPrivateKey) IDRequirement() (uint32, bool) { return p.idRequrement, p.HasIDRequirement() }
func (p *stubPrivateKey) HasIDRequirement() bool        { return p.prefixType != tinkpb.OutputPrefixType_RAW }
func (p *stubPrivateKey) PublicKey() (key.Key, error)   { return &stubPublicKey{}, nil }

type stubPrivateKeySerialization struct{}

var _ protoserialization.KeySerializer = (*stubPrivateKeySerialization)(nil)

func (s *stubPrivateKeySerialization) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         stubKeyURL,
			Value:           []byte("serialized_key"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
		},
		key.(*stubPrivateKey).prefixType,
		key.(*stubPrivateKey).idRequrement,
	)
}

type stubPrivateKeyParser struct{}

var _ protoserialization.KeyParser = (*stubPrivateKeyParser)(nil)

func (s *stubPrivateKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := serialization.IDRequirement()
	return &stubPrivateKey{serialization.OutputPrefixType(), idRequirement}, nil
}

func TestPrimitiveFactoryUsesFullPrimitiveIfRegistered(t *testing.T) {
	defer registryconfig.ClearPrimitiveConstructors()
	defer protoserialization.ClearKeyParsers()
	defer protoserialization.UnregisterKeySerializer[*stubPrivateKey]()

	if err := protoserialization.RegisterKeyParser(stubKeyURL, &stubPrivateKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPrivateKey](&stubPrivateKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	// Register a primitive constructor to make sure that the factory uses the
	// full primitive.
	primitiveConstructor := func(key key.Key) (any, error) { return &stubFullSigner{}, nil }
	if err := registryconfig.RegisterPrimitiveConstructor[*stubPrivateKey](primitiveConstructor); err != nil {
		t.Fatalf("registryconfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddKey(&stubPrivateKey{
		tinkpb.OutputPrefixType_TINK,
		0x1234,
	})
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

	signer, err := signature.NewSigner(handle)
	if err != nil {
		t.Fatalf("signature.NewSigner() err = %v, want nil", err)
	}
	data := []byte("data")
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign() err = %v, want nil", err)
	}
	if !bytes.Equal(signature, slices.Concat([]byte("full_signer_prefix"), data)) {
		t.Errorf("signature = %q, want: %q", signature, data)
	}
}

type stubLegacySigner struct{}

func (s *stubLegacySigner) Sign(data []byte) ([]byte, error) {
	return slices.Concat([]byte("legacy_signer_prefix"), data), nil
}

type stubKeyManager struct{}

var _ registry.KeyManager = (*stubKeyManager)(nil)

func (km *stubKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeyManager) DoesSupport(keyURL string) bool  { return keyURL == stubKeyURL }
func (km *stubKeyManager) TypeURL() string                 { return stubKeyURL }
func (km *stubKeyManager) Primitive(_ []byte) (any, error) { return &stubLegacySigner{}, nil }

func TestPrimitiveFactoryUsesLegacyPrimitive(t *testing.T) {
	defer protoserialization.ClearKeyParsers()
	defer protoserialization.UnregisterKeySerializer[*stubPrivateKey]()

	if err := protoserialization.RegisterKeyParser(stubKeyURL, &stubPrivateKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPrivateKey](&stubPrivateKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	if err := registry.RegisterKeyManager(&stubKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}

	data := []byte("data")
	legacyPrefix := []byte("legacy_signer_prefix")
	for _, tc := range []struct {
		name         string
		key          *stubPrivateKey
		wantSigature []byte
	}{
		{
			name:         "TINK",
			key:          &stubPrivateKey{tinkpb.OutputPrefixType_TINK, 0x1234},
			wantSigature: slices.Concat([]byte{cryptofmt.TinkStartByte, 0x00, 0x00, 0x12, 0x34}, legacyPrefix, data),
		},
		{
			name:         "LEGACY",
			key:          &stubPrivateKey{tinkpb.OutputPrefixType_LEGACY, 0x1234},
			wantSigature: slices.Concat([]byte{cryptofmt.LegacyStartByte, 0x00, 0x00, 0x12, 0x34}, legacyPrefix, data, []byte{0}),
		},
		{
			name:         "CRUNCHY",
			key:          &stubPrivateKey{tinkpb.OutputPrefixType_CRUNCHY, 0x1234},
			wantSigature: slices.Concat([]byte{cryptofmt.LegacyStartByte, 0x00, 0x00, 0x12, 0x34}, legacyPrefix, data),
		},
		{
			name:         "RAW",
			key:          &stubPrivateKey{tinkpb.OutputPrefixType_RAW, 0},
			wantSigature: slices.Concat(legacyPrefix, data),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create a keyset with a single key.
			km := keyset.NewManager()
			keyID, err := km.AddKey(tc.key)
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

			signer, err := signature.NewSigner(handle)
			if err != nil {
				t.Fatalf("signature.NewSigner() err = %v, want nil", err)
			}
			signature, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("signer.Sign() err = %v, want nil", err)
			}
			if !bytes.Equal(signature, tc.wantSigature) {
				t.Errorf("signature = %q, want: %q", signature, data)
			}
		})
	}
}
