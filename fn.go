//
// fn.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dohproxy

import (
	"log"
	"net/http"

	"github.com/markkurossi/cicd/api/auth"
	"github.com/markkurossi/go-libs/fn"
	"golang.org/x/crypto/ed25519"
)

var (
	mux        *http.ServeMux
	projectID  string
	store      *auth.ClientStore
	authPubkey ed25519.PublicKey
)

func init() {
	mux = http.NewServeMux()
	mux.HandleFunc("/dns-query", DNSQuery)

	id, err := fn.GetProjectID()
	if err != nil {
		log.Fatalf("fn.GetProjectID: %s\n", err)
	}
	projectID = id

	store, err = auth.NewClientStore()
	if err != nil {
		log.Fatalf("NewClientStore: %s\n", err)
	}
	assets, err := store.Asset(auth.ASSET_AUTH_PUBKEY)
	if err != nil {
		log.Fatalf("store.Asset(%s)\n", auth.ASSET_AUTH_PUBKEY)
	}
	if len(assets) == 0 {
		log.Fatalf("No auth public key\n")
	}
	authPubkey = ed25519.PublicKey(assets[0].Data)
}

func DoHProxy(w http.ResponseWriter, r *http.Request) {
	mux.ServeHTTP(w, r)
}
