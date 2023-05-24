# pfcaddy

Packetframe modules for Caddy

## Headers

| Direction        | Header                     | Description                                       |
|------------------|----------------------------|---------------------------------------------------|
| Request          | `PF-ForceChallenge`        | Force a challenge for the request                 |
| Request          | `PF-Debug`                 | Enable debugging headers                          |
| Response (debug) | `PF-Debug-HTTPGate-Expiry` | HTTPGate token expiry                             |
| Response (debug) | `PF-Debug-IsChallenging`   | "true"/"false" if the request is being challenged |
