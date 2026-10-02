# oauth2-application

[← Back to the main README](../README.md)

The use cases, and the ports they need from the outside world.

Depends on `oauth2-domain` and nothing else. No Spring: wiring happens in `oauth2-boot`, which is
what keeps the service constructible in a plain unit test.

## Inbound port

```java
public interface IssueClientCredentialsTokenUseCase {
    AccessToken issue(ClientCredentialsCommand command);
}
```

Returns the domain `AccessToken`, not a wire representation — the adapter derives `expires_in`
and the JSON shape from it.

## Outbound ports

| Port | Implemented by |
|---|---|
| `ClientRepository` | [in-memory](../oauth2-adapter/oauth2-adapter-out-persistence-inmemory/README.md) |
| `AccessTokenRepository` | [in-memory](../oauth2-adapter/oauth2-adapter-out-persistence-inmemory/README.md) |
| `AccessTokenGenerator` | [opaque](../oauth2-adapter/oauth2-adapter-out-token-opaque/README.md) or [JWT](../oauth2-adapter/oauth2-adapter-out-token-jwt/README.md) |
| `ClientSecretHasher` | [BCrypt](../oauth2-adapter/oauth2-adapter-out-secret-bcrypt/README.md) |
| `ClockPort` | [system clock](../oauth2-adapter/oauth2-adapter-out-time-system/README.md) |
| `TokenLifetimePort` | [fixed lifetime](../oauth2-adapter/oauth2-adapter-out-policy-fixed-lifetime/README.md) |

## `ClientCredentialsTokenService`

The order of the checks is a deliberate choice, because RFC 6749 specifies none:

1. `grant_type` absent → `invalid_request`
2. Client authentication → `invalid_client`
3. Grant unrecognised or unimplemented → `unsupported_grant_type`
4. Client not registered for the grant → `unauthorized_client`
5. Scope exceeds the registration → `invalid_scope`
6. Issue, save, return

Authentication runs **before** the grant type is recognised: §3.2.1 makes it a precondition, §5.2
defines `unauthorized_client` in terms of the *authenticated* client, and answering
`unsupported_grant_type` to an unauthenticated caller would confirm the server's grant registry
to anyone.

`GrantType` models every grant a registration may name; `SUPPORTED_GRANTS` is what this server
actually implements. The difference is why `authorization_code` is `unsupported_grant_type`
rather than `unauthorized_client`.

Authentication compares the presented secret against a stand-in hash when the client is unknown,
so response timing cannot be used to enumerate client ids.

## Test

```powershell
.\mvnw.cmd -pl oauth2-application test
```
