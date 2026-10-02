# oauth2-adapter-out-token-opaque

[← Back to the main README](../../README.md)

Issues opaque access tokens: 256 bits from a CSPRNG, Base64 URL encoded without padding.

Package `com.courinha.oauth2.core.adapter.out.token.opaque`.

`OpaqueTokenGenerator` implements `AccessTokenGenerator`.

RFC 6749 §1.4 leaves the token format to the server, and §10.10 requires the value to be
unpredictable. The token carries no meaning of its own — it is only a key into
`AccessTokenRepository`, which is what makes revocation a deletion.

This is the default format (`oauth2.token.format=opaque`).

## Test

```powershell
.\mvnw.cmd -pl oauth2-adapter/oauth2-adapter-out-token-opaque test
```
