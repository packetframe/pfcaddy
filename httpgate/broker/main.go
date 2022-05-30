package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"math/big"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	listen     = flag.String("l", ":8080", "listen address")
	hashExpiry = time.Hour
	verbose    = flag.Bool("v", false, "enable verbose logging")
)

var cache = make(map[string]time.Time) // server hash to expiration timestamp

const hexLetters = "0123456789abcdef"

// randomString returns a securely generated random string of specified length
func randomString(length int) (string, error) {
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(hexLetters))))
		if err != nil {
			return "", err
		}
		ret[i] = hexLetters[num.Int64()]
	}

	return string(ret), nil
}

// validate checks that a client provided token matches the given server hash
func validate(token, hash string) bool {
	_, found := cache[hash]
	if !found {
		return false
	}

	// Check if server hash is expired
	if time.Now().After(cache[hash]) {
		log.Debugf("Server hash %s expired, removing from cache", hash)
		delete(cache, hash)
		return false
	}

	return strings.HasSuffix(sha256hash(hash+token), "000")
}

func sha256hash(s string) string {
	fullHash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(fullHash[:])
}

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	// /validate?hash=<hash>&token=<token> to validate a token
	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		token := r.URL.Query().Get("token")

		w.Header().Set("Content-Type", "text/plain")
		if validate(token, hash) {
			log.Debugf("Valid token %s for hash %s", token, hash)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			log.Debugf("Invalid token %s for hash %s", token, hash)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	// /new to request a new token
	http.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
		newHash, err := randomString(32)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error"))
			return
		}
		cache[newHash] = time.Now().Add(hashExpiry)
		log.Debugf("Generated new hash %s", newHash)
		w.Write([]byte(newHash))
	})

	http.HandleFunc("/invalidate", func(w http.ResponseWriter, r *http.Request) {
		log.Debug("Invalidating all hashes")
		cache = make(map[string]time.Time)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("Starting httpgate token broker on %s", *listen)
	err := http.ListenAndServe(*listen, nil)
	if err != nil {
		log.Fatal(err)
	}
}
