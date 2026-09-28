# dsocket (Direct Socket)

A lightweight, zero-dependency, end-to-end encrypted (E2EE) rendezvous channel written in Go.

`dsocket` enables two machines behind NAT and firewalls to communicate securely without requiring port forwarding, static public IPs, or opening inbound firewall ports on either client.

---

## 🔒 Security Architecture

Unlike simple proxy tools or offensive backdoors, `dsocket` is designed strictly as a secure, authenticated peer-to-peer communication pipe:

1. **Zero-Knowledge Blind Relay (`pkg/relay`)**:
   - Clients derive a 32-byte public rendezvous ID from the shared secret: `HMAC-SHA256(secret, "dsocket-rendezvous-v1")`.
   - The relay server matches endpoints based solely on this blind hash.
   - The relay server **never** learns the secret passphrase and only sees encrypted ciphertext.

2. **Mutual Authenticated Key Exchange (`pkg/secureconn`)**:
   - Upon connection, peers exchange cryptographically random 32-byte salts.
   - Both sides compute unique session keys using RFC 5869 HKDF-SHA256:
     - `Key_AB` / `Key_BA`: Independent 256-bit AES symmetric keys for each direction.
     - `Auth_AB` / `Auth_BA`: HMAC keys for mutual authentication challenges.
   - Both peers execute a mutual HMAC verification handshake before processing any data stream. Mismatched secrets or tampering aborts immediately.

3. **AEAD Frame Transport**:
   - Every packet is encrypted with **AES-256-GCM**.
   - Frames include a 64-bit monotonically incrementing sequence number bound to Additional Authenticated Data (AAD) to prevent replay, truncation, or reordering attacks.

---

## 🚀 Quick & Ultra-Short Commands

You do **not** need long arguments. Default relay is used automatically (or set via `DSOCKET_RELAY`).

### 1. Send & Receive Files (Magic-Wormhole style)

**Sender:**
```bash
dsocket send myfile.pdf
```
> Outputs: `[*] Secret code: 74fq-xt67-jqb4`

**Receiver:**
```bash
dsocket recv 74fq-xt67-jqb4
```

---

### 2. Encrypted Netcat Pipe (Piping stdin/stdout across NAT)

**Host:**
```bash
dsocket -l
```
> Outputs: `[*] Secret code: 74fq-xt67-jqb4`

**Joiner:**
```bash
dsocket 74fq-xt67-jqb4
```

With custom passphrase:
```bash
# Host:
dsocket -l mypass

# Peer:
dsocket mypass
```

---

### 3. Relay Server

```bash
dsocket relay
# Or specify port:
dsocket relay :8765
```

---

### 4. TCP Port Forwarding

```bash
# Expose local port 3000 to tunnel:
dsocket forward -role host -target 127.0.0.1:3000 -s "mypass"

# Listen on local 8080 and forward across tunnel:
dsocket forward -role join -listen 127.0.0.1:8080 -s "mypass"
```


---

## 🧪 Running Tests

```bash
make test
```
