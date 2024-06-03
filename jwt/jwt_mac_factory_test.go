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
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"

	jwtmacpb "github.com/tink-crypto/tink-go/v2/proto/jwt_hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func newJWTHMACKey(algorithm jwtmacpb.JwtHmacAlgorithm, kid *jwtmacpb.JwtHmacKey_CustomKid) *jwtmacpb.JwtHmacKey {
	return &jwtmacpb.JwtHmacKey{
		Version:   0,
		Algorithm: algorithm,
		KeyValue:  random.GetRandomBytes(32),
		CustomKid: kid,
	}
}

func newKeyData(key *jwtmacpb.JwtHmacKey) (*tinkpb.KeyData, error) {
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.JwtHmacKey",
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

func createJWTMAC(keyData *tinkpb.KeyData, prefixType tinkpb.OutputPrefixType) (jwt.MAC, error) {
	primaryKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, prefixType)
	handle, err := testkeyset.NewHandle(testutil.NewKeyset(primaryKey.KeyId, []*tinkpb.Keyset_Key{primaryKey}))
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %v", err)
	}
	return jwt.NewMAC(handle)
}

func verifyMACCompareSubject(p jwt.MAC, compact string, validator *jwt.Validator, wantSubject string) error {
	verifiedJWT, err := p.VerifyMACAndDecode(compact, validator)
	if err != nil {
		return fmt.Errorf("p.VerifyMACAndDecode() err = %v, want nil", err)
	}
	subject, err := verifiedJWT.Subject()
	if err != nil {
		return fmt.Errorf("verifiedJWT.Subject() err = %v, want nil", err)
	}
	if subject != wantSubject {
		return fmt.Errorf("verifiedJWT.Subject() = %q, want %q", subject, wantSubject)
	}
	return nil
}

func TestNilKeyHandle(t *testing.T) {
	if _, err := jwt.NewMAC(nil); err == nil {
		t.Errorf("TestNilKeyHandle(nil) err = nil, want error")
	}
}

func TestFactorySameKeyMaterialWithRawPrefixAndNoKIDShouldIgnoreHeader(t *testing.T) {
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	p, err = createJWTMAC(keyData, tinkpb.OutputPrefixType_RAW)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err != nil {
		t.Errorf("VerifyMACAndDecode() with a RAW key err = %v, want nil", err)
	}
}

func TestFactorySameKeyMaterialWithDifferentPrefixAndKIDShouldFailVerification(t *testing.T) {
	key := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil)
	keyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	key.CustomKid = &jwtmacpb.JwtHmacKey_CustomKid{
		Value: "custom-kid",
	}
	rawKeyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err = createJWTMAC(rawKeyData, tinkpb.OutputPrefixType_RAW)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err == nil {
		t.Errorf("VerifyMACAndDecode() with a different KID = nil, want error")
	}
}

func TestFactoryDifferentKeyShouldFailValidation(t *testing.T) {
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("jwt.NewValidator() err = %v, want nil", err)
	}
	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	if err := verifyMACCompareSubject(p, compact, validator, "tink-subject"); err != nil {
		t.Error(err)
	}
	diffKey := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil)
	diffKeyData, err := newKeyData(diffKey)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err = createJWTMAC(diffKeyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err == nil {
		t.Errorf("VerifyMACAndDecode() with a different key = nil, want error")
	}
}

func TestFactoryWithRAWKeyAndKID(t *testing.T) {
	key := newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, &jwtmacpb.JwtHmacKey_CustomKid{Value: "custom-123"})
	keyData, err := newKeyData(key)
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	primaryKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, tinkpb.OutputPrefixType_RAW)
	ks := testutil.NewKeyset(primaryKey.KeyId, []*tinkpb.Keyset_Key{primaryKey})

	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("creating keyset handle: %v", err)
	}
	p, err := jwt.NewMAC(handle)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true, Subject: refString("tink-subject")})
	if err != nil {
		t.Errorf("NewRawJWT() err = %v, want nil", err)
	}

	compact, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Errorf("NewValidator() err = %v, want nil", err)
	}
	if _, err := p.VerifyMACAndDecode(compact, validator); err != nil {
		t.Errorf("p.VerifyMACAndDecode() err = %v, want nil", err)
	}
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}
	if _, err = jwt.NewMAC(kh); err == nil {
		t.Fatal("calling NewMAC() err = nil, want error")
	}
}

func TestVerifyMACAndDecodeReturnsValidationError(t *testing.T) {
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, nil))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	p, err := createJWTMAC(keyData, tinkpb.OutputPrefixType_TINK)
	if err != nil {
		t.Fatalf("creating New JWT MAC: %v", err)
	}

	audience := "audience"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{Audience: &audience, WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	token, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}

	otherAudience := "otherAudience"
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &otherAudience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}

	_, err = p.VerifyMACAndDecode(token, validator)
	wantErr := "validating audience claim: otherAudience not found"
	if err == nil {
		t.Errorf("p.VerifyMACAndDecode() err = nil, want %q", wantErr)
	}
	if err.Error() != wantErr {
		t.Errorf("p.VerifyMACAndDecode() err = %q, want %q", err.Error(), wantErr)
	}
}

func TestComputeAndVerifyWithoutAnnotationsEmitsNoMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	p, err := jwt.NewMAC(kh)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	audience := "audience"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{Audience: &audience, WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	token, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &audience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err = p.VerifyMACAndDecode(token, validator); err != nil {
		t.Errorf("p.VerifyMACAndDecode() err = %v, want error", err)
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want = 0", len(client.Failures()))
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want = 0", len(client.Events()))
	}
}

func TestComputeAndVerifyWithAnnotationsEmitsMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported through the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := jwt.NewMAC(mh)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	audience := "audience"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{Audience: &audience, WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	token, err := p.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Errorf("p.ComputeMACAndEncode() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &audience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err = p.VerifyMACAndDecode(token, validator); err != nil {
		t.Errorf("p.VerifyMACAndDecode() err = %v, want error", err)
	}
	failures := client.Failures()
	if len(failures) != 0 {
		t.Errorf("len(client.Failures()) = %d, want = 0", len(failures))
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.JwtHmacKey",
				KeyPrefix: "TINK",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    mh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: 1,
			Context:  monitoring.NewContext("jwtmac", "compute", wantKeysetInfo),
		},
		{
			KeyID:    mh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: 1,
			Context:  monitoring.NewContext("jwtmac", "verify", wantKeysetInfo),
		},
	}
	if cmp.Diff(got, want) != "" {
		t.Errorf("%v", cmp.Diff(got, want))
	}
}

func TestComputeFailureEmitsMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	keyData, err := newKeyData(newJWTHMACKey(jwtmacpb.JwtHmacAlgorithm_HS256, &jwtmacpb.JwtHmacKey_CustomKid{Value: "custom-kid"}))
	if err != nil {
		t.Fatalf("creating NewKeyData: %v", err)
	}
	primaryKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, tinkpb.OutputPrefixType_TINK)
	kh, err := testkeyset.NewHandle(testutil.NewKeyset(primaryKey.KeyId, []*tinkpb.Keyset_Key{primaryKey}))
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported through the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := jwt.NewMAC(mh)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	if _, err := p.ComputeMACAndEncode(rawJWT); err == nil {
		t.Errorf("p.ComputeMACAndEncode() err = nil, want error")
	}
	failures := client.Failures()
	if len(failures) != 1 {
		t.Errorf("len(client.Failures()) = %d, want = 1", len(failures))
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want = 0", len(client.Events()))
	}
}

func TestVerifyFailureEmitsMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported through the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := jwt.NewMAC(mh)
	if err != nil {
		t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
	}
	audience := "audience"
	validator, err := jwt.NewValidator(
		&jwt.ValidatorOpts{ExpectedAudience: &audience, AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	if _, err := p.VerifyMACAndDecode("", validator); err == nil {
		t.Errorf("p.VerifyMACAndDecode() err = nil, want error")
	}
	failures := client.Failures()
	if len(failures) != 1 {
		t.Errorf("len(client.Failures()) = %d, want = 1", len(failures))
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want = 0", len(client.Events()))
	}
}
