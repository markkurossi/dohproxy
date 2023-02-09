//
// sas.go
//
// Copyright (c) 2020-2023 Markku Rossi
//
// All rights reserved.
//

package dohproxy

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"regexp"
	"sync"

	"github.com/markkurossi/cloudsdk/api/auth"
)

// SA defines a security association.
type SA struct {
	ID  string
	Key []byte
}

var (
	reDNSQuery = regexp.MustCompilePOSIX(`^/sas/([^/]+)/dns-query$`)
	reSA       = regexp.MustCompilePOSIX(`^/sas/$`)

	sasM = new(sync.Mutex)
	sas  = make(map[string]*SA)
)

// CreateSA defines the attibutes for the security association
// creation request.
type CreateSA struct {
	SAs []*Envelope
}

// NewSARequest defines the attributes of the new security association.
type NewSARequest struct {
	ID  string `json:"id"`
	Key []byte `json:"key"`
}

// SAs handles security association creation and encrypted DNS
// queries.
func SAs(w http.ResponseWriter, r *http.Request) {
	token := auth.Authorize(w, r, REALM, tokenVerifier, tenant)
	if token == nil {
		return
	}
	if r.Method != "POST" {
		Errorf(w, http.StatusMethodNotAllowed, "%s", r.Method)
		return
	}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		Errorf(w, http.StatusInternalServerError,
			"error reading request body: %s", err)
		return
	}

	matches := reSA.FindStringSubmatch(r.URL.Path)
	if matches != nil {
		// Create new SA.
		create := new(CreateSA)
		err = json.Unmarshal(data, create)
		if err != nil {
			Errorf(w, http.StatusBadRequest, "error parsing request: %s", err)
			return
		}

		kp, err := GetEphemeralKeyPair()
		if err != nil {
			Errorf(w, http.StatusInternalServerError,
				"couldn't get keypair: %s", err)
			return
		}

		// Try to decode one of the envelopes.
		var payload []byte
		for _, env := range create.SAs {
			payload, err = env.Decrypt(kp)
			if err == nil {
				break
			}
		}
		if payload == nil {
			w.Header().Set("Content-Type", "application/x-509-user-cert")
			w.WriteHeader(http.StatusFailedDependency)
			w.Write(kp.cert.Raw)
			return
		}
		req := new(NewSARequest)
		err = json.Unmarshal(payload, req)
		if err != nil {
			Errorf(w, http.StatusBadRequest, "error parsing payload: %s", err)
			return
		}
		addSA(req.ID, req.Key)

		w.Header().Set("Content-Type", "application/x-509-user-cert")
		w.WriteHeader(http.StatusCreated)
		w.Write(kp.cert.Raw)
		return
	}
	matches = reDNSQuery.FindStringSubmatch(r.URL.Path)
	if matches != nil {
		// Encrypted DNS query.
		id := matches[1]
		sa := getSA(id)
		if sa == nil {
			Errorf(w, http.StatusNotFound, "SA '%s' not found", id)
			return
		}
		payload, err := Decrypt(sa.Key, data)
		if err != nil {
			Errorf(w, http.StatusBadRequest, "decrypt failed: %s", err)
			return
		}
		response, ok := doh(w, payload)
		if !ok {
			return
		}
		responseData, err := Encrypt(sa.Key, response)
		if err != nil {
			Errorf(w, http.StatusInternalServerError, "encrypt failed: %s", err)
			return
		}
		w.Write(responseData)
		return
	}

	Errorf(w, http.StatusNotFound, "Resource %s not found", r.URL.Path)
}

func addSA(id string, key []byte) {
	sasM.Lock()
	defer sasM.Unlock()

	sas[id] = &SA{
		ID:  id,
		Key: key,
	}
}

func getSA(id string) *SA {
	sasM.Lock()
	defer sasM.Unlock()

	return sas[id]
}
