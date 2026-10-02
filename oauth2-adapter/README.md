# oauth2-adapter

[← Back to the main README](../README.md)

Aggregator for the adapters. This module contains no code — it only groups the adapter artifacts
so each one can be depended on separately.

Every adapter is its own module, so a deployment picks exactly the ones it wants:

| Adapter | Port it implements |
|---|---|
| [oauth2-adapter-in-web](oauth2-adapter-in-web/README.md) | drives `IssueClientCredentialsTokenUseCase` |
| [oauth2-adapter-out-persistence-inmemory](oauth2-adapter-out-persistence-inmemory/README.md) | `ClientRepository`, `AccessTokenRepository` |
| [oauth2-adapter-out-token-opaque](oauth2-adapter-out-token-opaque/README.md) | `AccessTokenGenerator` |
| [oauth2-adapter-out-token-jwt](oauth2-adapter-out-token-jwt/README.md) | `AccessTokenGenerator` |
| [oauth2-adapter-out-secret-bcrypt](oauth2-adapter-out-secret-bcrypt/README.md) | `ClientSecretHasher` |
| [oauth2-adapter-out-time-system](oauth2-adapter-out-time-system/README.md) | `ClockPort` |
| [oauth2-adapter-out-policy-fixed-lifetime](oauth2-adapter-out-policy-fixed-lifetime/README.md) | `TokenLifetimePort` |

Each module uses its own package (`...adapter.out.token.opaque`, `...adapter.out.token.jwt`, and
so on) rather than sharing a package across jars, which keeps them free of split packages.

The choice is made in [`oauth2-boot`](../oauth2-boot/README.md)'s `pom.xml`. Swapping an adapter —
in-memory repositories for a database, opaque tokens for JWTs — touches that dependency list and
the wiring, never the domain or the use case.
