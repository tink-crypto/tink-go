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

package jwtecdsa

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"

	jwtecdsapb "github.com/tink-crypto/tink-go/v2/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"

type parametersSerializer struct{}

var _ protoserialization.ParametersSerializer = (*parametersSerializer)(nil)

func algorithmToProto(a Algorithm) jwtecdsapb.JwtEcdsaAlgorithm {
	switch a {
	case ES256:
		return jwtecdsapb.JwtEcdsaAlgorithm_ES256
	case ES384:
		return jwtecdsapb.JwtEcdsaAlgorithm_ES384
	case ES512:
		return jwtecdsapb.JwtEcdsaAlgorithm_ES512
	}
	return jwtecdsapb.JwtEcdsaAlgorithm_ES_UNKNOWN
}

func algorithmFromProto(a jwtecdsapb.JwtEcdsaAlgorithm) Algorithm {
	switch a {
	case jwtecdsapb.JwtEcdsaAlgorithm_ES256:
		return ES256
	case jwtecdsapb.JwtEcdsaAlgorithm_ES384:
		return ES384
	case jwtecdsapb.JwtEcdsaAlgorithm_ES512:
		return ES512
	}
	return UnknownAlgorithm
}

func outputPrefixTypeFromKIDStrategy(s KIDStrategy) tinkpb.OutputPrefixType {
	switch s {
	case CustomKID:
		return tinkpb.OutputPrefixType_RAW
	case IgnoredKID:
		return tinkpb.OutputPrefixType_RAW
	case Base64EncodedKeyIDAsKID:
		return tinkpb.OutputPrefixType_TINK
	}
	return tinkpb.OutputPrefixType_UNKNOWN_PREFIX
}

func kidStrategyFromOutputPrefixType(s tinkpb.OutputPrefixType) KIDStrategy {
	switch s {
	case tinkpb.OutputPrefixType_RAW:
		return IgnoredKID
	case tinkpb.OutputPrefixType_TINK:
		return Base64EncodedKeyIDAsKID
	}
	return UnknownKIDStrategy
}

func (s *parametersSerializer) Serialize(p key.Parameters) (*tinkpb.KeyTemplate, error) {
	if p == nil {
		return nil, fmt.Errorf("parameters can't be nil")
	}
	params, ok := p.(*Parameters)
	if !ok {
		return nil, fmt.Errorf("invalid parameters type: got %T, want %T", p, (*Parameters)(nil))
	}
	keyFormat := &jwtecdsapb.JwtEcdsaKeyFormat{
		Algorithm: algorithmToProto(params.Algorithm()),
		Version:   0,
	}
	serializedKeyFormat, err := proto.Marshal(keyFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JwtEcdsaKeyFormat: %v", err)
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          privateKeyTypeURL,
		Value:            serializedKeyFormat,
		OutputPrefixType: outputPrefixTypeFromKIDStrategy(params.kidStrategy),
	}, nil
}

type parametersParser struct{}

var _ protoserialization.ParametersParser = (*parametersParser)(nil)

func (s *parametersParser) Parse(kt *tinkpb.KeyTemplate) (key.Parameters, error) {
	if kt == nil {
		return nil, fmt.Errorf("key template can't be nil")
	}
	if kt.GetTypeUrl() != privateKeyTypeURL {
		return nil, fmt.Errorf("invalid type URL: got %q, want %q", kt.GetTypeUrl(), privateKeyTypeURL)
	}
	keyFormat := &jwtecdsapb.JwtEcdsaKeyFormat{}
	if err := proto.Unmarshal(kt.GetValue(), keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtEcdsaKeyFormat: %v", err)
	}
	if keyFormat.GetVersion() != 0 {
		return nil, fmt.Errorf("invalid version: got %d, want 0", keyFormat.GetVersion())
	}
	kidStrategy := kidStrategyFromOutputPrefixType(kt.GetOutputPrefixType())
	return NewParameters(kidStrategy, algorithmFromProto(keyFormat.GetAlgorithm()))
}
