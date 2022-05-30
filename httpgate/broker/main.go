package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var (
	listen     = flag.String("l", ":8080", "listen address")
	hashExpiry = time.Hour
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
		delete(cache, hash)
		return false
	}

	fullHash := sha256.Sum256([]byte(hash + token))
	return strings.HasSuffix(hex.EncodeToString(fullHash[:]), "000")
}

func sha256hash(s string) string {
	fullHash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(fullHash[:])
}

// solve a hash into a token
func solve(hash string) string {
	for {
		token, err := randomString(32)
		if err != nil {
			panic(err)
		}
		if strings.HasSuffix(hex.EncodeToString([]byte(sha256hash(sha256hash(hash+token)))), "000") {
			return token
		}
	}
}

func main() {
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		token := r.URL.Query().Get("token")

		w.Header().Set("Content-Type", "text/plain")
		if validate(token, hash) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			newHash, err := randomString(32)
			if err != nil {
				log.Println(err) // TODO: Sentry
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error"))
				return
			}
			cache[newHash] = time.Now().Add(hashExpiry)
			w.Write([]byte(newHash))
		}
	})

	http.HandleFunc("/invalidate", func(w http.ResponseWriter, r *http.Request) {
		cache = make(map[string]time.Time)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/solve", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(solve(r.URL.Query().Get("hash"))))
	})

	log.Printf("Starting l7dos token broker on %s", *listen)
	err := http.ListenAndServe(*listen, nil)
	if err != nil {
		log.Fatal(err)
	}
}
