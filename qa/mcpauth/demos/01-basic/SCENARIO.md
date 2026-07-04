# Demo 01 — Adding auth in front of an unauthenticated MCP server

Many MCP servers ship with **no authentication** — anyone who can reach the
port can invoke every tool. `mcpauth` drops a token-checking reverse proxy in
front of such a server without modifying it.

This demo is fully self-contained: it starts a tiny fake unauthenticated MCP
upstream, puts the `mcpauth` proxy in front of it, then fires two requests —
one **without** a token and one **with** a valid token.

## Run it

```bash
# Self-contained demonstration (spins up upstream + proxy internally):
python -m mcpauth demo
python -m mcpauth demo --format json
```

Or wire it up manually against the bundled token store:

```bash
# 1. The token whose hash lives in tokens.json was generated with:
#      python -m mcpauth gen-token --tokens demos/01-basic/tokens.json --label demo
#    (regenerate your own; the plaintext is shown only once.)

# 2. Start any unauthenticated MCP HTTP server on, say, 127.0.0.1:8000, then:
python -m mcpauth wrap \
    --upstream http://127.0.0.1:8000 \
    --tokens demos/01-basic/tokens.json \
    --port 9000

# 3. From another shell:
curl -i http://127.0.0.1:9000/mcp                       # -> 401 Unauthorized
curl -i -H "Authorization: Bearer <token>" \
        http://127.0.0.1:9000/mcp                        # -> 200 OK (forwarded)
```

## What it should show

| Request                        | Result | Why                                       |
|--------------------------------|--------|-------------------------------------------|
| No `Authorization` header      | `401`  | Missing Bearer token — rejected at proxy  |
| Bogus / unknown token          | `401`  | Constant-time hash compare fails          |
| Valid `Bearer <token>`         | `200`  | Authorized — request forwarded upstream   |

Every decision is emitted as a one-line JSON audit record on stdout, e.g.:

```json
{"ts":"...","client":"127.0.0.1","method":"GET","path":"/mcp","allowed":false,"reason":"missing_header","status":401,"token_id":"","label":""}
{"ts":"...","client":"127.0.0.1","method":"GET","path":"/mcp","allowed":true,"reason":"ok","status":200,"token_id":"a1b2c3d4","label":"demo-key"}
```

The `demo` subcommand exits `0` only if the no-token request got `401` **and**
the valid-token request got `200`.
