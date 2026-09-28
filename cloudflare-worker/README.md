# Cloudflare Worker Relay for dsocket

Run your own serverless, zero-maintenance global relay on **Cloudflare Workers**.

---

### Features

- ⚡ **Worldwide Edge:** Fast rendezvous pairing through Cloudflare data centers globally.
- 🛡️ **Firewall Friendly (Port 443):** Uses standard WebSocket over HTTPS (`wss://`), penetrating corporate and mobile firewalls.
- 🔒 **Zero-Knowledge:** Plaintext never touches Cloudflare. The worker only forwards opaque AES-256-GCM ciphertext frames.
- 💰 **Free Tier:** Runs on Cloudflare's free tier with zero server costs.

---

### Deploying to Cloudflare in 1 Minute

1. Navigate to this directory:
   ```bash
   cd cloudflare-worker
   ```

2. Log in to your Cloudflare account (if not already):
   ```bash
   npx wrangler login
   ```

3. Deploy:
   ```bash
   npx wrangler deploy
   ```

Wrangler will output your worker URL, e.g.:
```
https://dsocket-relay.<your-subdomain>.workers.dev
```

---

### Using with `dsocket`

Point `dsocket` to your worker via `wss://`:

```bash
# Export in ~/.bashrc or terminal:
export DSOCKET_RELAY="wss://dsocket-relay.<your-subdomain>.workers.dev"

# Now use dsocket normally:
dsocket send myfile.pdf
# Peer receives:
dsocket recv <secret>
```
