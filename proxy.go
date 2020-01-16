//
// proxy.go
//
// Copyright (c) 2020 Markku Rossi
//
// All rights reserved.
//

package dohproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/markkurossi/cicd/api/auth"
)

type Envelope struct {
	Data    string   `json:"data"`
	KeyInfo *KeyInfo `json:"key"`
}

type KeyInfo struct {
	Data string `json:"data"`
	ID   string `json:"id"`
}

type ProxyRequest struct {
	Data   string `json:"data"`
	Server string `json:"server"`
}

func DNSQuery(w http.ResponseWriter, r *http.Request) {
	token := auth.Authorize(w, r, REALM, tokenVerifier, tenant)
	if token == nil {
		return
	}
	if r.Method != "POST" {
		Errorf(w, http.StatusBadRequest, "Invalid method %s", r.Method)
		return
	}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		Errorf(w, http.StatusInternalServerError,
			"Error reading request body: %s", err)
		return
	}

	req := new(Envelope)
	err = json.Unmarshal(data, req)
	if err != nil {
		Errorf(w, http.StatusBadRequest, "Error parsing request: %s", err)
		return
	}

	q, server, key, err := decodeRequest(req)
	if err != nil {
		Errorf(w, http.StatusBadRequest, "Invalid DNS query data: %s", err)
		return
	}

	dnsReq, err := http.NewRequest("POST", server, bytes.NewReader(q))
	if err != nil {
		Errorf(w, http.StatusInternalServerError, "HTTP new request: %s", err)
		return
	}
	dnsReq.Header.Set("Content-Type", "application/dns-message")

	dnsResp, err := httpClient.Do(dnsReq)
	if err != nil {
		Errorf(w, http.StatusInternalServerError, "HTTP request: %s", err)
		return
	}
	defer dnsResp.Body.Close()

	dnsRespData, err := ioutil.ReadAll(dnsResp.Body)
	if err != nil {
		Errorf(w, http.StatusInternalServerError,
			"Error reading server response: %s", err)
		return
	}

	if dnsResp.StatusCode != http.StatusOK {
		Errorf(w, http.StatusBadGateway, "status=%s, content:\n%s",
			dnsResp.Status, hex.Dump(dnsRespData))
	}

	// Encrypt response
	encrypted, err := Encrypt(key[:32], key[32+12:], dnsRespData)
	if err != nil {
		Errorf(w, http.StatusInternalServerError,
			"Failed to encrypt response: %s", err)
		return
	}

	w.Write(encrypted)
}

func decodeRequest(env *Envelope) ([]byte, string, []byte, error) {
	if env.KeyInfo == nil {
		return nil, "", nil, fmt.Errorf("no key info")
	}

	kp, err := GetEphemeralKeyPair()
	if err != nil {
		return nil, "", nil, err
	}
	if kp.cert.SerialNumber.String() != env.KeyInfo.ID {
		return nil, "", nil, fmt.Errorf("Invalid key: %s vs. %s",
			kp.cert.SerialNumber, env.KeyInfo.ID)
	}
	keyData, err := base64.RawURLEncoding.DecodeString(env.KeyInfo.Data)
	if err != nil {
		return nil, "", nil, err
	}
	key, err := rsa.DecryptOAEP(sha256.New(), nil, kp.priv, keyData, nil)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to decode key: %s", err)
	}
	if len(key) != 32+2*12 {
		return nil, "", nil, fmt.Errorf("Invalid encryption key")
	}

	// Decrypt payload.

	payload, err := base64.RawURLEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, "", nil, err
	}
	data, err := Decrypt(key[:32], key[32:32+12], payload)
	if err != nil {
		return nil, "", nil, err
	}

	req := new(ProxyRequest)
	err = json.Unmarshal(data, req)
	if err != nil {
		return nil, "", nil, err
	}

	q, err := base64.RawURLEncoding.DecodeString(req.Data)
	if err != nil {
		return nil, "", nil, err
	}

	return q, req.Server, key[:], nil
}

func Encrypt(key, nonce, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce[:], data, nil), nil
}

func Decrypt(key, nonce, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, data, nil)
}

func Errorf(w http.ResponseWriter, code int, format string, a ...interface{}) {
	http.Error(w, fmt.Sprintf(format, a...), code)
}
