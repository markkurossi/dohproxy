//
// main.go
//
// Copyright (c) 2020 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"log"
	"os"

	"github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/markkurossi/dohproxy"
)

func main() {
	funcframework.RegisterHTTPFunction("/", dohproxy.DoHProxy)
	// Use PORT environment variable, or default to 8081.
	port := "8081"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	if err := funcframework.Start(port); err != nil {
		log.Fatalf("funcframework.Start: %v\n", err)
	}
}
