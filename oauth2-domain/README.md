# oauth2-domain

[← Back to the main README](../README.md)

The hexagon's core: the OAuth2 model, its rules, and the RFC 6749 error taxonomy.

Pure Java. No Spring, no `jakarta.*` — a `maven-enforcer` rule fails the build if either appears,
transitively included. Lombok is permitted, since it is a compile-time processor that leaves no
trace in the runtime classpath.

This module knows nothing about HTTP. Deciding what an error becomes on the wire is the web
adapter's job.

## Packages

| Package | Contents |
|---|---|
| `client` | `Client`, `ClientId`, `SecretHash`, `ClientType`, `GrantType`, `TokenEndpointAuthMethod` |
| `scope` | `Scope`, `ScopeSet` |
| `token` | `AccessToken`, `TokenType` |
| `error` | `OAuth2Error`, `OAuth2ErrorCode`, `OAuth2Exception` |
| `policy` | `ScopePolicy` |

## Rules worth knowing

- `OAuth2ErrorCode` lists only the codes §5.2 defines for the token endpoint. It deliberately
  omits `server_error` and `temporarily_unavailable`, which belong to the authorization endpoint
  (§4.1.2.1). An unexpected failure is not an OAuth error.
- `OAuth2Exception.invalidClient()` produces one fixed description for every authentication
  failure, so an unknown client and a wrong secret cannot be told apart by a caller.
- `Scope` enforces the §3.3 grammar, which excludes the space, `"`, `\`, control characters and
  non-ASCII. Scope tokens are case-sensitive.
- `ScopePolicy.resolve` uses the client's registered scopes as the documented default when the
  request omits `scope` — one of the two behaviours §3.3 permits.
- `AccessToken` models no refresh token, honouring §4.4.3 by construction. A test asserts its
  field set so the rule cannot erode silently.
- `SecretHash` and `AccessToken` redact themselves in `toString()`.

## Test

```powershell
.\mvnw.cmd -pl oauth2-domain test
```
