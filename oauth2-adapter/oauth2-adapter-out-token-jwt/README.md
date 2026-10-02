# oauth2-adapter-out-token-jwt

[← Back to the main README](../../README.md)

Issues self-contained HS256 JWTs (RFC 7519), hand-rolled on the JDK.

Package `com.courinha.oauth2.core.adapter.out.token.jwt`.

| Class | Responsibility |
|---|---|
| `JwtTokenGenerator` | Builds the header and claims, and signs them. |
| `JwtCodec` | Minimal JWS compact serialization: HS256 only. |

Enabled with `oauth2.token.format=jwt`.

A resource server can validate these without calling back. The trade-off is that revocation stops
being a deletion, which is why the application service still stores every token even when this
generator is selected.

## Why hand-rolled, and what it must get right

RFC 6749 says nothing about token format, so this is an implementation choice rather than
protocol work. The codec is deliberately narrow — one algorithm, no key management, no JWK sets —
and three details are easy to get subtly wrong:

- The signature covers the **encoded** header and payload, byte for byte, never a re-serialization
  of parsed JSON, which would not round-trip.
- Base64 must be the URL-safe alphabet **without padding**.
- Signature comparison must be constant-time, hence `MessageDigest.isEqual`.

The HMAC key must be at least 256 bits, checked when the codec is built, so a weak secret fails at
startup instead of producing forgeable tokens.

Claims are `iss`, `sub`, `client_id`, `scope`, `iat`, `exp`, `jti`. There is no `aud`, because no
resource server is registered yet and inventing an audience would be worse than omitting one.

## Test

```powershell
.\mvnw.cmd -pl oauth2-adapter/oauth2-adapter-out-token-jwt test
```
