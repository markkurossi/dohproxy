//
// proxy.go
//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package dohproxy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/markkurossi/cloudsdk/api/auth"
)

// ProxyRequest defines the attributes for the DNS proxy request.
type ProxyRequest struct {
	Data   []byte `json:"data"`
	Server string `json:"server"`
}

// DNSQuery implements handler for DNS queries.
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

	response, ok := doh(w, data)
	if !ok {
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(response)
}

func doh(w http.ResponseWriter, data []byte) ([]byte, bool) {
	req := new(ProxyRequest)
	err := json.Unmarshal(data, req)
	if err != nil {
		Errorf(w, http.StatusBadRequest, "error parsing request: %s", err)
		return nil, false
	}

	dnsReq, err := http.NewRequest("POST", req.Server,
		bytes.NewReader(req.Data))
	if err != nil {
		Errorf(w, http.StatusInternalServerError, "HTTP new request: %s", err)
		return nil, false
	}
	dnsReq.Header.Set("Content-Type", "application/dns-message")

	dnsResp, err := httpClient.Do(dnsReq)
	if err != nil {
		Errorf(w, http.StatusInternalServerError, "HTTP request: %s", err)
		return nil, false
	}
	defer dnsResp.Body.Close()

	dnsRespData, err := ioutil.ReadAll(dnsResp.Body)
	if err != nil {
		Errorf(w, http.StatusBadGateway,
			"error reading server response: %s", err)
		return nil, false
	}
	if dnsResp.StatusCode != http.StatusOK {
		Errorf(w, http.StatusBadGateway, "status=%s, content:\n%s",
			dnsResp.Status, hex.Dump(dnsRespData))
	}

	return dnsRespData, true
}
