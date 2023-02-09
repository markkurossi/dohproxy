//
// proxy.go
//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package dohproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// NonceLen defines the nonce length in bytes.
	NonceLen = 12
)

var (
	// ErrorInvalidKeyPair defines an error when envelope is encrypted
	// with an unknown key pair.
	ErrorInvalidKeyPair = errors.New("invalid key pair")
)

// Envelope defines a data container.
type Envelope struct {
	Data  []byte `json:"data"`
	KeyID string `json:"key_id"`
}

// Decrypt decrypts the envelope with the key pair.
func (env *Envelope) Decrypt(kp *KeyPair) ([]byte, error) {
	if kp.cert.SerialNumber.String() != env.KeyID {
		return nil, ErrorInvalidKeyPair
	}
	data, err := rsa.DecryptOAEP(sha256.New(), nil, kp.priv, env.Data, nil)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Encrypt encrypts the data with the key.
func Encrypt(key, data []byte) ([]byte, error) {
	var nonce [NonceLen]byte

	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encrypted := aesgcm.Seal(nil, nonce[:], data, nil)

	return append(nonce[:], encrypted...), nil
}

// Decrypt decrypts the data with the key.
func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < NonceLen {
		return nil, fmt.Errorf("truncated encrypted payload: len=%d", len(data))
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, data[:NonceLen], data[NonceLen:], nil)
}
