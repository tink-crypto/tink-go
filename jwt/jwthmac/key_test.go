// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/Lycense-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package jwthmac_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/jwt/jwthmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

type keyTestCase struct {
	name       string
	opts       jwthmac.KeyOpts
	wantKID    string
	wantHasKID bool
}

func keyTestCases(t *testing.T) []keyTestCase {
	var tcs []keyTestCase

	for _, algorithmAndKeyBytes := range []struct {
		algorithm jwthmac.Algorithm
		key       secretdata.Bytes
	}{
		{jwthmac.HS256, secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{})},
		{jwthmac.HS384, secretdata.NewBytesFromData([]byte("012345678901234567890123456789012345678901234567"), insecuresecretdataaccess.Token{})},
		{jwthmac.HS512, secretdata.NewBytesFromData([]byte("0123456789012345678901234567890101234567890123456789012345678901"), insecuresecretdataaccess.Token{})}} {
		for _, kidStrategyAndValues := range []struct {
			strategy      jwthmac.KIDStrategy
			idRequirement uint32
			customKID     string
			hasCustomKID  bool
			wantKID       string
			wantHasKID    bool
		}{
			{
				strategy:      jwthmac.Base64EncodedKeyIDAsKID,
				idRequirement: 0x01020304,
				customKID:     "",
				hasCustomKID:  false,
				wantKID:       "AQIDBA",
				wantHasKID:    true,
			},
			{
				strategy:      jwthmac.CustomKID,
				idRequirement: 0,
				customKID:     "custom_kid",
				hasCustomKID:  true,
				wantKID:       "custom_kid",
				wantHasKID:    true,
			},
			{
				strategy:      jwthmac.IgnoredKID,
				idRequirement: 0,
				customKID:     "",
				hasCustomKID:  false,
				wantKID:       "",
				wantHasKID:    false,
			},
		} {
			tcs = append(tcs, keyTestCase{
				name: fmt.Sprintf("%s_%d_%s", algorithmAndKeyBytes.algorithm, algorithmAndKeyBytes.key.Len(), kidStrategyAndValues.strategy),
				opts: jwthmac.KeyOpts{
					KeyBytes:      algorithmAndKeyBytes.key,
					IDRequirement: kidStrategyAndValues.idRequirement,
					CustomKID:     kidStrategyAndValues.customKID,
					HasCustomKID:  kidStrategyAndValues.hasCustomKID,
					Parameters:    mustCreateParameters(t, algorithmAndKeyBytes.key.Len(), kidStrategyAndValues.strategy, algorithmAndKeyBytes.algorithm),
				},
				wantKID:    kidStrategyAndValues.wantKID,
				wantHasKID: kidStrategyAndValues.wantHasKID,
			})
		}
	}
	return tcs
}

func TestKey(t *testing.T) {
	for _, tc := range keyTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			k, err := jwthmac.NewKey(tc.opts)
			if err != nil {
				t.Fatalf("NewKey(%v) failed: %v", tc.opts, err)
			}
			kid, hasKID := k.KID()
			if kid != tc.wantKID || hasKID != tc.wantHasKID {
				t.Errorf("k.KID() = %q, %v, want %q, %v", kid, hasKID, tc.wantKID, tc.wantHasKID)
			}
			if !k.KeyBytes().Equal(tc.opts.KeyBytes) {
				t.Errorf("k.KeyBytes() = %v, want %v", k.KeyBytes(), tc.opts.KeyBytes)
			}

			params := k.Parameters()
			if !params.Equal(tc.opts.Parameters) {
				t.Errorf("k.Parameters() = %v, want %v", params, tc.opts.Parameters)
			}

			idRequirement, hasIDRequirement := k.IDRequirement()
			if idRequirement != tc.opts.IDRequirement || hasIDRequirement != tc.opts.Parameters.HasIDRequirement() {
				t.Errorf("k.IDRequirement() = %v, %v, want %v, %v", idRequirement, hasIDRequirement, tc.opts.IDRequirement, tc.opts.Parameters.HasIDRequirement())
			}

			k2, err := jwthmac.NewKey(tc.opts)
			if err != nil {
				t.Fatalf("NewKey(%v) failed: %v", tc.opts, err)
			}
			if diff := cmp.Diff(k, k2); diff != "" {
				t.Errorf("NewKey(%v) returned unexpected diff (-want +got):\n%s", tc.opts, diff)
			}
		})
	}
}

func TestPublicKeyEqual_Different(t *testing.T) {
	keyBytes1 := secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{})
	keyBytes2 := secretdata.NewBytesFromData([]byte("012345678901234567890123456AAAAA"), insecuresecretdataaccess.Token{})
	keyBytes3 := secretdata.NewBytesFromData([]byte("012345678901234567890123456789012"), insecuresecretdataaccess.Token{})
	for _, tc := range []struct {
		name         string
		opts1, opts2 jwthmac.KeyOpts
	}{
		{
			name: "DifferentKeyBytes",
			opts1: jwthmac.KeyOpts{
				KeyBytes:      keyBytes1,
				Parameters:    mustCreateParameters(t, keyBytes1.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
			opts2: jwthmac.KeyOpts{
				KeyBytes:      keyBytes2, // Different bytes
				Parameters:    mustCreateParameters(t, keyBytes2.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
		},
		{
			name: "DifferentKeySizes",
			opts1: jwthmac.KeyOpts{
				KeyBytes:      keyBytes1,
				Parameters:    mustCreateParameters(t, keyBytes1.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
			opts2: jwthmac.KeyOpts{
				KeyBytes:      keyBytes3, // Different size
				Parameters:    mustCreateParameters(t, keyBytes3.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
		},
		{
			name: "DifferentKIDStrategy",
			opts1: jwthmac.KeyOpts{
				KeyBytes:      keyBytes1,
				Parameters:    mustCreateParameters(t, keyBytes1.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
			opts2: jwthmac.KeyOpts{
				KeyBytes:     keyBytes1,
				Parameters:   mustCreateParameters(t, keyBytes1.Len(), jwthmac.CustomKID, jwthmac.HS256), // Different KID strategy
				CustomKID:    "some_kid",
				HasCustomKID: true,
			},
		},
		{
			name: "DifferentIDRequirement",
			opts1: jwthmac.KeyOpts{
				KeyBytes:      keyBytes1,
				Parameters:    mustCreateParameters(t, keyBytes1.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
			opts2: jwthmac.KeyOpts{
				KeyBytes:      keyBytes1,
				Parameters:    mustCreateParameters(t, keyBytes1.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x05060708, // Different ID requirement
			},
		},
		{
			name: "DifferentAlgorithm",
			opts1: jwthmac.KeyOpts{
				KeyBytes:      keyBytes1,
				Parameters:    mustCreateParameters(t, keyBytes1.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
			opts2: jwthmac.KeyOpts{
				KeyBytes:      secretdata.NewBytesFromData([]byte("012345678901234567890123456789012345678901234567"), insecuresecretdataaccess.Token{}),
				Parameters:    mustCreateParameters(t, 48, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS384), // Different algorithm
				IDRequirement: 0x01020304,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k1, err := jwthmac.NewKey(tc.opts1)
			if err != nil {
				t.Fatalf("NewKey(%v) failed: %v", tc.opts1, err)
			}
			k2, err := jwthmac.NewKey(tc.opts2)
			if err != nil {
				t.Fatalf("NewKey(%v) failed: %v", tc.opts2, err)
			}

			if cmp.Equal(k1, k2) {
				t.Errorf("cmp.Equal(%v, %v) = true, want false", k1, k2)
			}
		})
	}
}

func TestNewKey_Errors(t *testing.T) {
	keyBytes := secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{})
	for _, tc := range []struct {
		name string
		opts jwthmac.KeyOpts
	}{
		{
			name: "NilParameters",
			opts: jwthmac.KeyOpts{
				KeyBytes:      keyBytes,
				IDRequirement: 0x01020304,
				Parameters:    nil,
			},
		},
		{
			name: "IDRequirementNotRequiredButSet",
			opts: jwthmac.KeyOpts{
				KeyBytes:      keyBytes,
				Parameters:    mustCreateParameters(t, keyBytes.Len(), jwthmac.IgnoredKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
		},
		{
			name: "KeySizeMismatch",
			opts: jwthmac.KeyOpts{
				KeyBytes:      keyBytes,
				Parameters:    mustCreateParameters(t, keyBytes.Len()+1, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
			},
		},
		{
			name: "Base64EncodedKeyIDAsKID_CustomKIDSet",
			opts: jwthmac.KeyOpts{
				KeyBytes:      keyBytes,
				Parameters:    mustCreateParameters(t, keyBytes.Len(), jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				IDRequirement: 0x01020304,
				CustomKID:     "some_kid",
				HasCustomKID:  true,
			},
		},
		{
			name: "IgnoredKID_CustomKIDSet",
			opts: jwthmac.KeyOpts{
				KeyBytes:     keyBytes,
				Parameters:   mustCreateParameters(t, keyBytes.Len(), jwthmac.IgnoredKID, jwthmac.HS256),
				CustomKID:    "some_kid",
				HasCustomKID: true,
			},
		},
		{
			name: "CustomKID_CustomKIDNotSet",
			opts: jwthmac.KeyOpts{
				KeyBytes:     keyBytes,
				Parameters:   mustCreateParameters(t, keyBytes.Len(), jwthmac.CustomKID, jwthmac.HS256),
				HasCustomKID: false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jwthmac.NewKey(tc.opts); err == nil {
				t.Errorf("NewKey(%v) err = nil, want error", tc.opts)
			} else {
				t.Logf("NewKey(%v) err = %v", tc.opts, err)
			}
		})
	}
}

func TestKeyCreator(t *testing.T) {
	for _, tc := range []struct {
		kidStrategy    jwthmac.KIDStrategy
		algorithm      jwthmac.Algorithm
		idRequirement  uint32
		keySizeInBytes int
	}{
		{jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256, 0x01020304, 32},
		{jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS384, 0x01020304, 48},
		{jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS512, 0x01020304, 64},
		{jwthmac.IgnoredKID, jwthmac.HS256, 0, 32},
		{jwthmac.IgnoredKID, jwthmac.HS384, 0, 48},
		{jwthmac.IgnoredKID, jwthmac.HS512, 0, 64},
	} {
		t.Run(fmt.Sprintf("%v_%v_%d", tc.kidStrategy, tc.algorithm, tc.keySizeInBytes), func(t *testing.T) {
			params := mustCreateParameters(t, tc.keySizeInBytes, tc.kidStrategy, tc.algorithm)
			key, err := keygenregistry.CreateKey(params, tc.idRequirement)
			if err != nil {
				t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
			}
			jwthmacKey, ok := key.(*jwthmac.Key)
			if !ok {
				t.Fatalf("keygenregistry.CreateKey() returned key of type %T, want %T", key, (*jwthmac.Key)(nil))
			}

			idRequirement, hasIDRequirement := jwthmacKey.IDRequirement()
			if tc.kidStrategy == jwthmac.Base64EncodedKeyIDAsKID {
				if !hasIDRequirement || idRequirement != tc.idRequirement {
					t.Errorf("jwthmacKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0x01020304, true)
				}
			} else {
				if hasIDRequirement {
					t.Errorf("jwthmacKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0, false)
				}
			}
			if diff := cmp.Diff(jwthmacKey.Parameters(), params); diff != "" {
				t.Errorf("jwthmacKey.Parameters() diff (-want +got): \n%s", diff)
			}
		})
	}
}

func TestKeyCreator_Errors(t *testing.T) {
	for _, tc := range []struct {
		kidStrategy    jwthmac.KIDStrategy
		algorithm      jwthmac.Algorithm
		keySizeInBytes int
	}{
		{jwthmac.CustomKID, jwthmac.HS256, 32},
		{jwthmac.CustomKID, jwthmac.HS384, 48},
		{jwthmac.CustomKID, jwthmac.HS512, 64},
	} {
		t.Run(fmt.Sprintf("%v_%v", tc.kidStrategy, tc.algorithm), func(t *testing.T) {
			params := mustCreateParameters(t, tc.keySizeInBytes, tc.kidStrategy, tc.algorithm)
			if _, err := keygenregistry.CreateKey(params, 0); err == nil {
				t.Errorf("keygenregistry.CreateKey() err = nil, want error")
			} else {
				t.Logf("keygenregistry.CreateKey() err = %v", err)
			}
		})
	}
}
