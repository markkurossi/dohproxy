//
// certificate.go
//
// Copyright (c) 2020 Markku Rossi
//
// All rights reserved.
//

package dohproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/markkurossi/cloudsdk/api/auth"
)

type KeyPair struct {
	priv *rsa.PrivateKey
	cert *x509.Certificate
}

var (
	keyPairM = new(sync.Mutex)
	keyPair  *KeyPair
	subject  = pkix.Name{
		Organization: []string{"markkurossi.com"},
		CommonName:   REALM,
	}
	template = &x509.Certificate{
		IsCA:           false,
		KeyUsage:       x509.KeyUsageDataEncipherment,
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
)

func GetEphemeralKeyPair() (*KeyPair, error) {
	keyPairM.Lock()
	defer keyPairM.Unlock()

	now := time.Now()

	if keyPair == nil || now.After(keyPair.cert.NotAfter) {
		// Create a new keypair.
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		var buf [64]byte
		_, err = rand.Read(buf[:])
		if err != nil {
			return nil, err
		}

		subject.OrganizationalUnit = []string{projectID}

		template.SerialNumber = new(big.Int).SetBytes(buf[:])
		template.Subject = subject
		template.Issuer = subject
		template.NotBefore = now
		template.NotAfter = now.Add(24 * time.Hour)

		data, err := x509.CreateCertificate(rand.Reader, template, template,
			&priv.PublicKey, priv)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, err
		}
		keyPair = &KeyPair{
			priv: priv,
			cert: cert,
		}
	}
	return keyPair, nil
}

func Certificate(w http.ResponseWriter, r *http.Request) {
	token := auth.Authorize(w, r, REALM, tokenVerifier, tenant)
	if token == nil {
		return
	}
	if r.Method != "GET" {
		Errorf(w, http.StatusMethodNotAllowed, "%s", r.Method)
		return
	}

	keyPair, err := GetEphemeralKeyPair()
	if err != nil {
		Errorf(w, http.StatusInternalServerError,
			"error getting ephemeral key pair: %s", err)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-user-cert")
	w.Write(keyPair.cert.Raw)
}
