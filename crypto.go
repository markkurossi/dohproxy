//
// proxy.go
//
// Copyright (c) 2020 Markku Rossi
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
	NONCE_LEN = 12
)

var (
	ErrorInvalidKeyPair = errors.New("invalid key pair")
)

type Envelope struct {
	Data  []byte `json:"data"`
	KeyID string `json:"key_id"`
}

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

func Encrypt(key, data []byte) ([]byte, error) {
	var nonce [NONCE_LEN]byte

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

func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < NONCE_LEN {
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
	return aesgcm.Open(nil, data[:NONCE_LEN], data[NONCE_LEN:], nil)
}
