# DID/VC Issuer — W3C Verifiable Credentials

> **Status:** ✅ Merged to main (PR #29, v0.22.0)

BOTCHA is a W3C DID/VC issuer. It has the decentralized identifier `did:web:botcha.ai` and can issue W3C Verifiable Credential (VC) JWTs to verified agents. Credentials are portable — any party can verify them offline using BOTCHA's public JWKS, with no round-trip to BOTCHA required.

## BOTCHA's DID Document

```bash
GET /.well-known/did.json
```

Returns BOTCHA's DID Document conforming to the [DID Core spec](https://www.w3.org/TR/did-core/). Includes verification methods (public keys) used to sign issued credentials.

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:botcha.ai",
  "verificationMethod": [
    {
      "id": "did:web:botcha.ai#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:botcha.ai",
      "publicKeyJwk": { ... }
    }
  ],
  "assertionMethod": ["did:web:botcha.ai#key-1"]
}
```

## JWK Set

```bash
GET /.well-known/jwks
GET /.well-known/jwks.json    # alias — some resolvers append .json
```

Returns the JWK Set containing all BOTCHA public keys (both TAP agent signing keys and DID/VC signing keys). Use this to verify issued credentials offline.

## Issuing a Credential

Requires a valid BOTCHA Bearer token (obtained via challenge-solve or x402 payment).

```bash
POST /v1/credentials/issue
Authorization: Bearer <botcha-token>
Content-Type: application/json

{
  "subject": {
    "id": "did:web:myagent.example",
    "name": "MyAgent",
    "operator": "Acme Corp"
  },
  "type": ["VerifiableCredential", "BotchaVerification"]
}
```

**Response:**
```json
{
  "vc": "eyJ...",
  "type": "BotchaVerification",
  "issuer": "did:web:botcha.ai",
  "issuanceDate": "2026-02-20T17:39:00Z"
}
```

The `vc` field is a signed JWT. The payload follows [JWT-VC](https://www.w3.org/TR/vc-data-model/#json-web-token) encoding.

**Decoded payload shape:**
```json
{
  "iss": "did:web:botcha.ai",
  "sub": "did:web:myagent.example",
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "BotchaVerification"],
    "credentialSubject": {
      "id": "did:web:myagent.example",
      "name": "MyAgent",
      "operator": "Acme Corp"
    }
  },
  "iat": 1740072000,
  "exp": 1740158400
}
```

## Verifying a Credential

Public endpoint — no auth required.

```bash
POST /v1/credentials/verify
Content-Type: application/json

{
  "vc": "eyJ..."
}
```

**Response on success:**
```json
{
  "valid": true,
  "payload": { ... }
}
```

Verification checks JWT signature against BOTCHA's JWKS, expiry, and issuer (`did:web:botcha.ai`). Returns `503` if the server is not configured (e.g. signing key missing).

## Resolving DID Documents

```bash
GET /v1/dids/did:web:myagent.example/resolve
```

Resolves any `did:web` DID by fetching `https://myagent.example/.well-known/did.json`. Returns the parsed DID Document or an error.

## Offline Verification Pattern

Because BOTCHA signs credentials with an asymmetric key published in `/.well-known/jwks`, recipients can:

1. Fetch BOTCHA's JWKS once and cache it
2. Verify any `vc` JWT locally without calling BOTCHA

```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('https://botcha.ai/.well-known/jwks'));

const { payload } = await jwtVerify(vcJwt, JWKS, {
  issuer: 'did:web:botcha.ai',
});
```

## Known Limitations

- `POST /v1/credentials/verify` returns `503` (not `200`) when the server's signing key is not configured — this is intentional to distinguish "verified" from "couldn't check."
- Credential revocation is not yet supported — once issued, a VC is valid until its `exp` claim.

## References

- [W3C DID Core spec](https://www.w3.org/TR/did-core/)
- [W3C VC Data Model](https://www.w3.org/TR/vc-data-model/)
- [did:web method spec](https://w3c-ccg.github.io/did-method-web/)
- [JWT-VC encoding](https://www.w3.org/TR/vc-data-model/#json-web-token)
- BOTCHA DID: `did:web:botcha.ai`
