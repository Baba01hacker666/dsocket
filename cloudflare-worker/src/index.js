/**
 * dsocket-relay: Cloudflare Worker + Durable Objects
 * 
 * Provides global, zero-knowledge, serverless rendezvous relaying
 * for dsocket end-to-end encrypted tunnels over WebSockets (WSS).
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health / Info landing page
    if (url.pathname === "/" || url.pathname === "") {
      return new Response(
        JSON.stringify({
          service: "dsocket-relay",
          status: "online",
          protocol: "dsocket-wss-v1",
          usage: "Connect via WebSocket to /relay?id=<hex_rendezvous_id>&role=<host|join>"
        }, null, 2),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // WebSocket Relay Endpoint
    if (url.pathname === "/relay" || url.pathname.startsWith("/ws")) {
      const upgradeHeader = request.headers.get("Upgrade");
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
        return new Response("Expected WebSocket Upgrade", { status: 426 });
      }

      const sessionId = url.searchParams.get("id");
      if (!sessionId || sessionId.length < 16) {
        return new Response("Missing or invalid 'id' parameter (min 16 chars)", { status: 400 });
      }

      // Route to unique Durable Object instance for this session ID
      const doId = env.RELAY_DO.idFromName(sessionId);
      const stub = env.RELAY_DO.get(doId);
      return stub.fetch(request);
    }

    return new Response("Not Found", { status: 404 });
  }
};

/**
 * RelaySession Durable Object
 * 
 * Pairs host and joiner WebSocket connections worldwide and bridges
 * encrypted binary frames between them.
 */
export class RelaySession {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.hostWs = null;
    this.joinerWs = null;
    this.timeoutId = null;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const role = url.searchParams.get("role") || "host";

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    server.accept();

    if (role === "host") {
      if (this.hostWs) {
        try {
          this.hostWs.close(1008, "Session already active with another host");
        } catch (e) {}
      }
      this.hostWs = server;
      this.bindSocket(server, "host");
    } else {
      this.joinerWs = server;
      this.bindSocket(server, "join");

      // If host is already waiting, trigger match notification to both
      if (this.hostWs) {
        // StatusMatched byte: 0x20
        const matchedSignal = new Uint8Array([0x20]);
        this.hostWs.send(matchedSignal);
        this.joinerWs.send(matchedSignal);
      }
    }

    this.resetTimeout();
    return new Response(null, { status: 101, webSocket: client });
  }

  bindSocket(ws, role) {
    ws.addEventListener("message", (event) => {
      this.resetTimeout();
      const peer = role === "host" ? this.joinerWs : this.hostWs;
      if (peer && peer.readyState === WebSocket.OPEN) {
        peer.send(event.data);
      }
    });

    ws.addEventListener("close", () => {
      if (role === "host") {
        this.hostWs = null;
        if (this.joinerWs && this.joinerWs.readyState === WebSocket.OPEN) {
          try { this.joinerWs.close(1000, "Host disconnected"); } catch (e) {}
        }
      } else {
        this.joinerWs = null;
        if (this.hostWs && this.hostWs.readyState === WebSocket.OPEN) {
          try { this.hostWs.close(1000, "Joiner disconnected"); } catch (e) {}
        }
      }
    });

    ws.addEventListener("error", () => {
      try { ws.close(); } catch (e) {}
    });
  }

  resetTimeout() {
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
    }
    // 5 minutes idle cleanup
    this.timeoutId = setTimeout(() => {
      if (this.hostWs) try { this.hostWs.close(1000, "Idle timeout"); } catch (e) {}
      if (this.joinerWs) try { this.joinerWs.close(1000, "Idle timeout"); } catch (e) {}
    }, 5 * 60 * 1000);
  }
}
