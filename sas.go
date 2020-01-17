//
// sas.go
//
// Copyright (c) 2020 Markku Rossi
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

	"github.com/markkurossi/cicd/api/auth"
)

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

type NewSARequest struct {
	ID  string `json:"id"`
	Key []byte `json:"key"`
}

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
		env := new(Envelope)
		err = json.Unmarshal(data, env)
		if err != nil {
			Errorf(w, http.StatusBadRequest, "error parsing envelope: %s", err)
			return
		}
		payload, err := env.Decrypt()
		if err != nil {
			if err == ErrorInvalidKeyPair {
				Errorf(w, http.StatusFailedDependency,
					"encryption key mismatch")
			} else {
				Errorf(w, http.StatusBadRequest,
					"error decrypting request: %s", err)
			}
			return
		}
		req := new(NewSARequest)
		err = json.Unmarshal(payload, req)
		if err != nil {
			Errorf(w, http.StatusBadRequest, "error parsing payload: %s", err)
			return
		}
		addSA(req.ID, req.Key)
		w.WriteHeader(http.StatusCreated)
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
