# httpgate

HTTP (D)DoS mitigation and bot management system

1. Server sends a random hex string to the client
2. Client brute forces a random hex string such that `SHA256(SHA256(server's string + client's string))` has at least n leading zeroes in binary
3. Client sends its string to the server
4. Server checks if the client's string is correct

- TODO: ratelimiting on session broker to avoid resource exhaustion
- TODO: compress challenge page to be as small as possible
- TODO: sentry
