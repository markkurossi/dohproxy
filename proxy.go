//
// proxy.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dohproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/markkurossi/cicd/api/auth"
	"golang.org/x/crypto/ed25519"
)

func verifier(message, sig []byte) bool {
	return ed25519.Verify(authPubkey, message, sig)
}

type ProxyRequest struct {
	Data   string `json:"data"`
	Server string `json:"server"`
}

func DNSQuery(w http.ResponseWriter, r *http.Request) {
	token := auth.Authorize(w, r, "DNS-over-HTTPS Proxy", verifier, tenant)
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

	req := new(ProxyRequest)
	err = json.Unmarshal(data, req)
	if err != nil {
		Errorf(w, http.StatusBadRequest, "Error parsing request: %s", err)
		return
	}

	q, err := base64.RawURLEncoding.DecodeString(req.Data)
	if err != nil {
		Errorf(w, http.StatusBadRequest, "Invalid DNS query data: %s", err)
		return
	}

	dnsReq, err := http.NewRequest("POST", req.Server, bytes.NewReader(q))
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

	w.Write(dnsRespData)
}

func Errorf(w http.ResponseWriter, code int, format string, a ...interface{}) {
	http.Error(w, fmt.Sprintf(format, a...), code)
}
