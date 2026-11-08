# jwt-debug-toolkit

**Decode JWT** header and payload (Base64URL), inspect standard claims (`exp`, `nbf`, `iat`), and get a short **summary for debugging**—no signature verification (by design; use your auth library for that).

```js
const { inspectJwt } = require('jwt-debug-toolkit');

const info = inspectJwt(process.argv[2]);

console.log(info.summaryLines.join('\n'));
console.log('expired?', info.isExpired);
console.log('expires in (s):', info.expiresInSeconds);
```

## Install

```bash
npm install jwt-debug-toolkit
```

## API

### `decodeJwt(token)`

Parses the three segments; returns `{ header, payload, signature, raw }`. Throws on malformed tokens.

```js
const { decodeJwt } = require('jwt-debug-toolkit');

const parts = decodeJwt(token);
console.log(parts.payload.sub);
```

### `inspectJwt(token, nowSeconds?)`

Adds:

| Field | Description |
| --- | --- |
| `issues` | Missing `alg`, clock problems, etc. |
| `exp` / `nbf` / `iat` | Numeric timestamps when present |
| `isExpired` / `expiresInSeconds` | Relative to `now` (default: current time) |
| `summaryLines` | One-liners for logs or REPL output |

Optional `nowSeconds` fixes tests at a known clock.

## When to use

- Support scripts and local CLI debugging of access tokens
- Logging why a token looks wrong before you trace Auth0/OIDC config
- **Not** for verifying trust—always validate signatures and issuers in production middleware

## Why teams pick this

**vs jwt.io in browser:** decode and summarise `exp`/`nbf` in Node scripts—no verify, no leak to web.

**Search terms:** jwt decode, jwt debug, json web token, claims, exp, nbf, base64url, authentication debug, node, typescript
