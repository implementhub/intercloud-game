# Intercloud Secure Game

## Secure Cross-Domain Rock-Paper-Scissors using SPIFFE, Federation and WebPKI

---

# 1. Introduction

This project implements a distributed and secure Rock-Paper-Scissors game using SPIFFE/SPIRE for workload identity and mutual TLS authentication.

The system demonstrates:

* Secure service-to-service authentication using SPIFFE
* Mutual TLS (mTLS)
* Federation between independent trust domains
* A cryptographically secure commit-reveal game protocol
* Public HTTPS endpoints secured via ACME / Let’s Encrypt
* CLI-based gameplay with score tracking

The project combines Zero-Trust identity principles with WebPKI-based public trust.

---

# 2. System Architecture

## Components

The system consists of:

* SPIRE Server (Primary Trust Domain)
* SPIRE Server (Secondary Trust Domain)
* SPIRE Agent (per VM)
* Game Clients (client1, client2)
* Bundle HTTPS Service
* Score HTTPS Endpoint (ACME secured)

## Communication Types

| Communication             | Technology            |
| ------------------------- | --------------------- |
| Game ↔ Game               | SPIFFE mTLS           |
| Cross-Domain Trust        | SPIFFE Federation     |
| Trust Bundle Distribution | HTTPS (ACME)          |
| Score Endpoint            | HTTPS (Let’s Encrypt) |

Internal identity is handled via SPIFFE.
Public endpoints are secured using WebPKI certificates.

---

# 3. SPIFFE mTLS – Single Trust Domain

## SPIRE Setup

SPIRE Server and Agent are started according to lab configuration.

Server readiness:

```
curl http://127.0.0.1:8080/ready
```

Agent readiness:

```
curl http://127.0.0.1:8082/ready
```

## Workload Registration

Clients are registered as SPIFFE workloads:

```
spire-server entry create \
  -spiffeID spiffe://<trust-domain>/client1 \
  -parentID spiffe://<trust-domain>/agent \
  -selector unix:uid:<UID> \
  -selector unix:path:<path>/spiffe-helper \
  -x509SVIDTTL 300
```

Properties:

* Identification via Unix UID and binary path
* Short-lived X.509 SVIDs (TTL 300 seconds)
* Automatic certificate rotation

## Certificate Rotation

Certificates are renewed using:

```
./spiffe-helper -config helper.conf -daemon-mode=false
```

Generated files:

* svid.pem
* svid_key.pem
* svid_bundle.pem

## Mutual TLS Enforcement

The Game Service enforces strict mTLS:

```python
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(...)
context.load_verify_locations(...)
context.verify_mode = ssl.CERT_REQUIRED
```

Security guarantees:

* Client certificate is mandatory
* Validation against trust bundle
* No unauthenticated access possible

---

# 4. SPIFFE Federation – Cross Domain

## Federation Configuration

Primary trusts Secondary:

```
spire-server federation create \
  -trustDomain <secondary-domain> \
  -bundleEndpointURL https://localhost:8543 \
  -endpointSpiffeID spiffe://<secondary>/spire/server
```

Secondary trusts Primary analogously.

## Federation for Workloads

Workloads were registered with:

```
-federatesWith <other-domain>
```

Additionally, helper.conf was updated:

```
include_federated_domains = true
```

## Testing

Successfully tested:

* Cross-domain gameplay between two different trust domains
* Gameplay within the same trust domain
* mTLS verification using federated bundles

Cross-domain authentication works reliably.

---

# 5. Cross-Domain Authentication

Peer SPIFFE IDs are extracted directly from the TLS certificate:

```python
peer_cert = handler.connection.getpeercert()
...
if entry[0] == 'URI':
    return entry[1]
```

Properties:

* Identity extracted from SAN URI
* Identity-based access control
* No IP-based authentication
* Only authenticated workloads can play

This fulfills cross-domain workload authentication requirements.

---

# 6. Commit-Reveal Game Protocol

To guarantee fairness, a 3-message protocol is implemented.

## Protocol Flow

1. Challenge → Commitment sent
2. Response → Opponent sends move
3. Reveal → Move + Salt disclosed
4. Verify → Hash verification
5. Result → Winner determined

## Commitment Calculation

```python
hashlib.sha256(f"{move}{salt}".encode()).hexdigest()
```

## Security Properties

* Move remains secret until reveal
* Salt prevents preimage attacks
* Commitment verification before result
* Tampering results in verification failure
* Ties trigger replay

---

# 7. CLI Interface and Score Tracking

Game start:

```
python3 game-service.py --port 9001 --target https://localhost:9002
```

Scores are stored in memory:

```python
scores = {
  "spiffe://client2": {"wins": 2, "losses": 1}
}
```

Structured logs provide full traceability:

```
[GAME] New round started
[COMMIT] Commitment created
[RESPONSE] Move received
[REVEAL] Reveal received
[VERIFY] Commitment verification successful
[RESULT] rock vs scissors → win
[SCORE] spiffe://client2 → Wins: 3 | Losses: 1
```

The CLI supports:

* Starting new games
* Ending the session
* Viewing score progression

---

# 8. WebPKI / ACME Integration

Public HTTPS endpoints are secured via Let’s Encrypt certificates.

## Score Endpoint

Accessible via:

```
https://<domain>:9004/score
```

Properties:

* ACME HTTP-01 challenge
* Publicly trusted CA
* Independent from SPIFFE trust

## Bundle Endpoint

```
bundle-service.py --port 9005
```

Properties:

* HTTPS secured
* ACME certificate
* Federation-compatible

This demonstrates separation between internal SPIFFE trust and public WebPKI trust.

---

# 9. Logging & Observability

Structured logging includes:

* Timestamp
* Log category
* Game state
* Result summary

Sensitive data such as salts and private keys are never logged.

Example:

```
[GAME] Round started
[COMMIT] Commitment generated
[REVEAL] Reveal validated
[RESULT] Player1 wins
[SCORE] Updated scoreboard
```

---

# 10. Security Analysis

| Security Goal            | Implementation         |
| ------------------------ | ---------------------- |
| Mutual Authentication    | SPIFFE mTLS            |
| Identity-Based Access    | SPIFFE ID validation   |
| Replay Protection        | Commit-Reveal protocol |
| Cross-Domain Trust       | Federation             |
| Public Trust             | ACME / Let’s Encrypt   |
| Short-Lived Certificates | TTL 300 seconds        |

Zero-Trust principles are consistently applied.

---

# 11. Limitations

* No Docker containerization
* No Kubernetes deployment
* No OAuth integration
* No OPA policy engine
* Score stored only in memory

---

# 12. Conclusion

The project successfully implements:

* SPIFFE-based workload identity
* Federation between independent trust domains
* Secure commit-reveal protocol
* CLI gameplay with score tracking
* ACME-secured public HTTPS endpoints
* Cross-domain authenticated gameplay

All core requirements have been fully implemented and tested.

---

If you want, I can also provide:

* A shorter README version (for public repo)
* A more technical version (for grading)
* Diagrams in Markdown (Mermaid)
* A “How to Run” section added at the top
