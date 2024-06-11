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

package jwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	jepb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestSignerVerifierFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}
	if _, err := jwt.NewSigner(kh); err == nil {
		t.Errorf("jwt.NewSigner() err = nil, want error")
	}
	if _, err := jwt.NewVerifier(kh); err == nil {
		t.Errorf("jwt.NewVerifier() err = nil, want error")
	}
}

func TestSignerVerifierFactoryNilKeyset(t *testing.T) {
	if _, err := jwt.NewSigner(nil); err == nil {
		t.Errorf("jwt.NewSigner(nil) err = nil, want error")
	}
	if _, err := jwt.NewVerifier(nil); err == nil {
		t.Errorf("jwt.NewVerifier(nil) err = nil, want error")
	}
}

func createJWTECDSAKey(kid *string) (*jepb.JwtEcdsaPrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey(curve=P256): %v", err)
	}
	var customKID *jepb.JwtEcdsaPublicKey_CustomKid = nil
	if kid != nil {
		customKID = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *kid}
	}
	return &jepb.JwtEcdsaPrivateKey{
		Version: 0,
		PublicKey: &jepb.JwtEcdsaPublicKey{
			Version:   0,
			Algorithm: jepb.JwtEcdsaAlgorithm_ES256,
			X:         k.X.Bytes(),
			Y:         k.Y.Bytes(),
			CustomKid: customKID,
		},
		KeyValue: k.D.Bytes(),
	}, nil
}

func createKeyData(privKey *jepb.JwtEcdsaPrivateKey) (*tinkpb.KeyData, error) {
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		return nil, fmt.Errorf("serializing private key proto: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
		Value:           serializedPrivKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func createKeysetHandles(privKey *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType) (*keyset.Handle, *keyset.Handle, error) {
	k := testutil.NewKey(privKey, tinkpb.KeyStatusType_ENABLED, 1 /*=keyID*/, outputPrefixType)
	privKeyHandle, err := testkeyset.NewHandle(testutil.NewKeyset(k.KeyId, []*tinkpb.Keyset_Key{k}))
	if err != nil {
		return nil, nil, fmt.Errorf("creating keyset handle for private key: %v", err)
	}
	pubKeyHandle, err := privKeyHandle.Public()
	if err != nil {
		return nil, nil, fmt.Errorf("creating keyset handle for public key: %v", err)
	}
	return privKeyHandle, pubKeyHandle, nil
}

func createKeyHandlesFromKey(t *testing.T, privKey *jepb.JwtEcdsaPrivateKey, outputPrefixType tinkpb.OutputPrefixType) (*keyset.Handle, *keyset.Handle) {
	privKeyData, err := createKeyData(privKey)
	if err != nil {
		t.Fatal(err)
	}
	privKeyHandle, pubKeyHandle, err := createKeysetHandles(privKeyData, outputPrefixType)
	if err != nil {
		t.Fatal(err)
	}
	return privKeyHandle, pubKeyHandle
}

func createKeyAndKeyHandles(t *testing.T, kid *string, outputPrefixType tinkpb.OutputPrefixType) (*jepb.JwtEcdsaPrivateKey, *keyset.Handle, *keyset.Handle) {
	privKey, err := createJWTECDSAKey(kid)
	if err != nil {
		t.Fatal(err)
	}
	privKeyHandle, pubKeyHandle := createKeyHandlesFromKey(t, privKey, outputPrefixType)
	return privKey, privKeyHandle, pubKeyHandle
}

func TestFactoryVerifyWithDifferentKeyFails(t *testing.T) {
	_, privKeyHandle, pubKeyHandle := createKeyAndKeyHandles(t, nil /*=kid*/, tinkpb.OutputPrefixType_TINK)

	signer, err := jwt.NewSigner(privKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Audiences: []string{"tink-audience"}})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true, ExpectedAudience: refString("tink-audience")})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}

	// verification with different key fails
	_, _, pubKeyHandle = createKeyAndKeyHandles(t, nil /*=kid*/, tinkpb.OutputPrefixType_TINK)
	verifier, err = jwt.NewVerifier(pubKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err == nil {
		t.Errorf("verifier.VerifyAndDecode() err = nil, want error")
	}
}

func TestFactorySignWithTinkAndCustomKIDFails(t *testing.T) {
	_, privKeyHandle, _ := createKeyAndKeyHandles(t, refString("customKID"), tinkpb.OutputPrefixType_TINK)
	signer, err := jwt.NewSigner(privKeyHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	if _, err := signer.SignAndEncode(rawJWT); err == nil {
		t.Errorf("signer.SignAndEncode() err = nil, want error")
	}
}

type signerVerifierFactoryKIDTestCase struct {
	tag                  string
	signerOutputPrefix   tinkpb.OutputPrefixType
	signerKID            *string
	verifierOutputPrefix tinkpb.OutputPrefixType
	verifierKID          *string
}

func TestFactorySignVerifyWithKIDFailure(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	for _, tc := range []signerVerifierFactoryKIDTestCase{
		{
			tag:                  "raw output prefix and different custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("OtherCustomKID"),
		},
		{
			tag:                  "verifier with tink output prefix and custom kid when token has no kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          refString("customKID"),
		},
		{
			tag:                  "verifier with tink output prefix and custom kid when token has kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          refString("customKid"),
		},
		{
			tag:                  "token with fixed kid and verifier with tink output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
		{
			tag:                  "token missing kid in header when verifier has tink output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			key, privKeyHandle, _ := createKeyAndKeyHandles(t, tc.signerKID, tc.signerOutputPrefix)
			signer, err := jwt.NewSigner(privKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
			}

			key.PublicKey.CustomKid = nil
			if tc.verifierKID != nil {
				key.PublicKey.CustomKid = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *tc.verifierKID}
			}
			_, pubKeyHandle := createKeyHandlesFromKey(t, key, tc.verifierOutputPrefix)
			verifier, err := jwt.NewVerifier(pubKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err == nil {
				t.Errorf("verifier.VerifyAndDecode() err = nil, want error")
			}
		})
	}
}

func TestVerifyAndDecodeReturnsValidationError(t *testing.T) {
	_, privateHandle, publicHandle := createKeyAndKeyHandles(t, nil /*=kid*/, tinkpb.OutputPrefixType_TINK)
	signer, err := jwt.NewSigner(privateHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}

	audience := "audience"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{Audience: &audience, WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}

	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
	}

	otherAudience := "otherAudience"
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &otherAudience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	_, err = verifier.VerifyAndDecode(compact, validator)
	wantErr := "validating audience claim: otherAudience not found"
	if err == nil {
		t.Errorf("verifier.VerifyAndDecode() err = nil, want %q", wantErr)
	}
	if err.Error() != wantErr {
		t.Errorf("verifier.VerifyAndDecode() err = %q, want %q", err.Error(), wantErr)
	}
}

func TestFactorySignVerifyWithKIDSuccess(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	for _, tc := range []signerVerifierFactoryKIDTestCase{
		{
			tag:                "signer verifier without custom kid and with raw output prefix",
			signerOutputPrefix: tinkpb.OutputPrefixType_RAW,
			signerKID:          nil,

			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "signer with custom kid verifier without custom kid and raw output prefixes",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "signer and verifier same custom kid and raw output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            refString("customKID"),
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("customKID"),
		},
		{
			tag:                  "signer and verifier with tink output prefix and no custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_TINK,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_TINK,
			verifierKID:          nil,
		},
		{
			tag:                  "signer with tink output prefix verifier with raw output prefix",
			signerOutputPrefix:   tinkpb.OutputPrefixType_TINK,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          nil,
		},
		{
			tag:                  "token missing kid in header when verifier has custom kid",
			signerOutputPrefix:   tinkpb.OutputPrefixType_RAW,
			signerKID:            nil,
			verifierOutputPrefix: tinkpb.OutputPrefixType_RAW,
			verifierKID:          refString("customKID"),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			key, privKeyHandle, _ := createKeyAndKeyHandles(t, tc.signerKID, tc.signerOutputPrefix)
			signer, err := jwt.NewSigner(privKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Errorf("signer.SignAndEncode() err = %v, want nil", err)
			}

			key.GetPublicKey().CustomKid = nil
			if tc.verifierKID != nil {
				key.GetPublicKey().CustomKid = &jepb.JwtEcdsaPublicKey_CustomKid{Value: *tc.verifierKID}
			}
			_, pubKeyHandle := createKeyHandlesFromKey(t, key, tc.verifierOutputPrefix)
			verifier, err := jwt.NewVerifier(pubKeyHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}
		})
	}
}

func TestFactorySignVerifyWithoutAnnotationsEmitsNoMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	signer, err := jwt.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
}

func TestFactorySignWithAnnotationsEmitsMonitoringSuccess(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(jwt.ES256Template())
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
	// Verify annotations aren't propagated.
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	signer, err := jwt.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
	// verify error emits no monitoring.
	if _, err := verifier.VerifyAndDecode("invalid", validator); err == nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
	if len(client.Events()) != 1 {
		t.Errorf("len(client.Events()) = %d, want 1", len(client.Events()))
	}
	got := client.Events()
	wantSignKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.JwtEcdsaPrivateKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("jwtsign", "sign", wantSignKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: 1,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestFactoryVerifyWithAnnotationsEmitsMonitoringSuccess(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	signer, err := jwt.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}

	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
	if len(client.Events()) != 1 {
		t.Errorf("len(client.Events()) = %d, want 1", len(client.Events()))
	}
	got := client.Events()
	wantSignKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.JwtEcdsaPublicKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("jwtverify", "verify", wantSignKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: 1,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestFactorySignAndVerifyWithAnnotationsEmitsMonitoringOnError(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kid := "intrusive_kid"
	_, privHandle, pubHandle := createKeyAndKeyHandles(t, &kid, tinkpb.OutputPrefixType_TINK)
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(privHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	signer, err := jwt.NewSigner(privHandle)
	if err != nil {
		t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	verifier, err := jwt.NewVerifier(pubHandle)
	if err != nil {
		t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err := signer.SignAndEncode(rawJWT); err == nil {
		t.Fatalf("signer.SignAndEncode() err = nil, want error")
	}
	if _, err := verifier.VerifyAndDecode("invalid_token", validator); err == nil {
		t.Fatalf("verifier.VerifyAndDecode() err = nil want error")
	}
	if len(client.Failures()) != 2 {
		t.Errorf("len(client.Failures()) = %d, want 2", len(client.Failures()))
	}
}
