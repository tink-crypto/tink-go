// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...

package registry

import (
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	keyManagersMu  sync.RWMutex
	keyManagers    = make(map[string]KeyManager) // typeURL -> KeyManager
	kmsClientsMu   sync.RWMutex
	kmsClients     = []KMSClient{}
	registryLocked bool
)

// LockRegistry prevents further modification of the registry after initialization.
// Once locked, no new KeyManagers can be registered or unregistered.
func LockRegistry() {
	keyManagersMu.Lock()
	defer keyManagersMu.Unlock()
	registryLocked = true
}

// RegisterKeyManager registers the given key manager.
// Does not allow to overwrite existing key managers.
func RegisterKeyManager(keyManager KeyManager) error {
	keyManagersMu.Lock()
	defer keyManagersMu.Unlock()

	if registryLocked {
		return fmt.Errorf("registry.RegisterKeyManager: registry is locked")
	}

	typeURL := keyManager.TypeURL()
	if _, existed := keyManagers[typeURL]; existed {
		return fmt.Errorf("registry.RegisterKeyManager: type %s already registered", typeURL)
	}
	keyManagers[typeURL] = keyManager
	return nil
}

// GetKeyManager returns the key manager for the given typeURL if existed.
func GetKeyManager(typeURL string) (KeyManager, error) {
	keyManagersMu.RLock()
	defer keyManagersMu.RUnlock()
	keyManager, existed := keyManagers[typeURL]
	if !existed {
		return nil, fmt.Errorf("registry.GetKeyManager: unsupported key type: %s", typeURL)
	}
	return keyManager, nil
}

// NewKeyData generates a new KeyData for the given key template.
func NewKeyData(template *tinkpb.KeyTemplate) (*tinkpb.KeyData, error) {
	if template == nil {
		return nil, fmt.Errorf("registry.NewKeyData: invalid key template")
	}
	keyManager, err := GetKeyManager(template.TypeUrl)
	if err != nil {
		return nil, err
	}
	return keyManager.NewKeyData(template.Value)
}

// NewKey generates a new key for the given key template.
//
// Deprecated: use [NewKeyData] instead.
func NewKey(template *tinkpb.KeyTemplate) (proto.Message, error) {
	if template == nil {
		return nil, fmt.Errorf("registry.NewKey: invalid key template")
	}
	keyManager, err := GetKeyManager(template.TypeUrl)
	if err != nil {
		return nil, err
	}
	return keyManager.NewKey(template.Value)
}

// PrimitiveFromKeyData creates a new primitive for the key given in the given KeyData.
func PrimitiveFromKeyData(keyData *tinkpb.KeyData) (any, error) {
	if keyData == nil {
		return nil, fmt.Errorf("registry.PrimitiveFromKeyData: invalid key data")
	}
	return Primitive(keyData.TypeUrl, keyData.Value)
}

// Primitive creates a new primitive for the given serialized key using the KeyManager.
func Primitive(typeURL string, serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("registry.Primitive: invalid serialized key")
	}
	keyManager, err := GetKeyManager(typeURL)
	if err != nil {
		return nil, err
	}
	return keyManager.Primitive(serializedKey)
}

// RegisterKMSClient is used to register a new KMS client.
func RegisterKMSClient(kmsClient KMSClient) {
	kmsClientsMu.Lock()
	defer kmsClientsMu.Unlock()
	kmsClients = append(kmsClients, kmsClient)
}

// GetKMSClient fetches a KMSClient by a given URI.
func GetKMSClient(keyURI string) (KMSClient, error) {
	kmsClientsMu.RLock()
	defer kmsClientsMu.RUnlock()
	for _, kmsClient := range kmsClients {
		if kmsClient.Supported(keyURI) {
			return kmsClient, nil
		}
	}
	return nil, fmt.Errorf("KMS client supporting %s not found", keyURI)
}

// ClearKMSClients removes all registered KMS clients.
func ClearKMSClients() {
	kmsClientsMu.Lock()
	defer kmsClientsMu.Unlock()
	kmsClients = []KMSClient{}
}

// UnregisterKeyManager unregisters the key manager for the given typeURL.
// This function is intended to be used in tests only and is an internal API.
func UnregisterKeyManager(typeURL string, _ internalapi.Token) {
	keyManagersMu.Lock()
	defer keyManagersMu.Unlock()

	if registryLocked {
		panic("registry.UnregisterKeyManager: registry is locked")
	}

	delete(keyManagers, typeURL)
}