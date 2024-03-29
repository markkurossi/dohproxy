//
// fn.go
//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package dohproxy

import (
	"fmt"
	"net/http"
	"os"

	"github.com/markkurossi/cloudsdk/api/auth"
	"github.com/markkurossi/go-libs/fn"
	"golang.org/x/crypto/ed25519"
)

const (
	// REALM defines the OAuth2 authentication realm.
	REALM = "DNS-over-HTTPS Proxy"
	// TENANT defines the OAuth2 authentication tenant.
	TENANT = "DNS-over-HTTPS-proxy"
)

var (
	mux        *http.ServeMux
	projectID  string
	store      *auth.ClientStore
	tenant     *auth.Tenant
	authPubkey ed25519.PublicKey
	httpClient *http.Client
)

func init() {
	mux = http.NewServeMux()
	mux.HandleFunc("/certificate", Certificate)
	mux.HandleFunc("/dns-query", DNSQuery)
	mux.HandleFunc("/sas/", SAs)

	id, err := fn.GetProjectID()
	if err != nil {
		Fatalf("fn.GetProjectID: %s\n", err)
	}
	projectID = id

	store, err = auth.NewClientStore()
	if err != nil {
		Fatalf("NewClientStore: %s\n", err)
	}
	tenants, err := store.TenantByName(TENANT)
	if err != nil {
		Fatalf("store.TenantByName: %s\n", err)
	}
	if len(tenants) == 0 {
		Fatalf("Tenant %s not found\n", TENANT)
	}
	tenant = tenants[0]

	assets, err := store.Asset(auth.ASSET_AUTH_PUBKEY)
	if err != nil {
		Fatalf("store.Asset(%s)\n", auth.ASSET_AUTH_PUBKEY)
	}
	if len(assets) == 0 {
		Fatalf("No auth public key\n")
	}
	authPubkey = ed25519.PublicKey(assets[0].Data)

	httpClient = new(http.Client)
}

// DoHProxy implements the Google Cloud Functions entrypoint.
func DoHProxy(w http.ResponseWriter, r *http.Request) {
	mux.ServeHTTP(w, r)
}

func tokenVerifier(message, sig []byte) bool {
	return ed25519.Verify(authPubkey, message, sig)
}

// Errorf returns an HTTP error.
func Errorf(w http.ResponseWriter, code int, format string, a ...interface{}) {
	http.Error(w, fmt.Sprintf(format, a...), code)
}

// Fatalf prints a fatal error and exits the program.
func Fatalf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}
