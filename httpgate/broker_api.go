package httpgate

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

const broker = "http://localhost:8080"

// newHash requests a new hash from the broker
func newHash() (string, error) {
	resp, err := http.Get(broker + "/new")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// validate verifies a token/hash against the broker
func validate(httpGate string) (bool, error) {
	parts := strings.Split(httpGate, ":")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid token")
	}
	hash := parts[0]
	token := parts[1]
	resp, err := http.Get(fmt.Sprintf("%s/validate?hash=%s&token=%s", broker, hash, token))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}
