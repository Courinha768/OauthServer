# OAuth2 Authorization Server

An OAuth2 authorization server implementing **RFC 6749** from scratch, built on a hexagonal
(ports and adapters) architecture.

No Spring Security and no Spring Authorization Server — the protocol is implemented here, so
every rule is visible and testable.

## Status

**Iteration 1: the `client_credentials` grant (§4.4), end to end.**

The token endpoint is complete for this grant, with both opaque and JWT tokens. The
authorization endpoint, consent, and refresh tokens are not implemented yet.

## Modules

Each module has its own README.

| Module | What it is |
|---|---|
| [oauth2-domain](oauth2-domain/README.md) | The hexagon's core: OAuth2 model, rules and error taxonomy. No framework dependencies. |
| [oauth2-application](oauth2-application/README.md) | Use cases and the ports they need. |
| [oauth2-adapter](oauth2-adapter/README.md) | Aggregator for the adapters. Each one is a separate module so they can be mixed and matched. |
| [oauth2-boot](oauth2-boot/README.md) | Spring Boot composition root: wires adapters to ports and starts the server. |

### Adapters

| Adapter | What it is |
|---|---|
| [in-web](oauth2-adapter/oauth2-adapter-in-web/README.md) | The token endpoint, over plain Spring WebMVC. |
| [out-persistence-inmemory](oauth2-adapter/oauth2-adapter-out-persistence-inmemory/README.md) | Map-backed client and token repositories. |
| [out-persistence-file](oauth2-adapter/oauth2-adapter-out-persistence-file/README.md) | The same repositories, backed by JSON files. |
| [out-token-opaque](oauth2-adapter/oauth2-adapter-out-token-opaque/README.md) | Random opaque access tokens. |
| [out-token-jwt](oauth2-adapter/oauth2-adapter-out-token-jwt/README.md) | Self-contained HS256 JWTs, hand-rolled on the JDK. |
| [out-secret-bcrypt](oauth2-adapter/oauth2-adapter-out-secret-bcrypt/README.md) | BCrypt client secret hashing. |
| [out-time-system](oauth2-adapter/oauth2-adapter-out-time-system/README.md) | The system clock. |
| [out-policy-fixed-lifetime](oauth2-adapter/oauth2-adapter-out-policy-fixed-lifetime/README.md) | One configured access token lifetime. |

## Dependency direction

```
domain  <-  application  <-  adapter  <-  boot
```

Dependencies point inward. `oauth2-domain` cannot depend on Spring or `jakarta.*` — a
`maven-enforcer` rule fails the build if it tries. `oauth2-boot` depends on exactly the adapters
it wants, so swapping one is a change to its `pom.xml` and nothing else.

## Build

The JDK must be on `JAVA_HOME`; it is not assumed to be on `PATH`.

```powershell
$env:JAVA_HOME = "C:\Users\anton\.jdks\openjdk-25.0.1"
.\mvnw.cmd clean verify
```

## Run

```powershell
.\mvnw.cmd -pl oauth2-boot spring-boot:run
```

Two demo clients are seeded at startup: `demo-basic` (registered for `client_secret_basic`) and
`demo-post` (registered for `client_secret_post`), both with secret `secret`. A third,
`demo-special`, has a secret full of characters that require RFC 6749 Appendix B encoding.

To run against the file-backed repositories instead, set
`oauth2.persistence.repository=file`. That registry starts empty — the file is the operator's
source of truth — so either add a client to `clients.json` or set
`oauth2.file.persistence.seed-demo-clients=true` for the first run.

## Try it

```bash
# client_secret_basic
curl -si -u demo-basic:secret \
  -d "grant_type=client_credentials&scope=read" \
  http://localhost:8080/oauth2/token

# client_secret_post
curl -si -d "grant_type=client_credentials&client_id=demo-post&client_secret=secret" \
  http://localhost:8080/oauth2/token

# a wrong secret: expect 401 with WWW-Authenticate
curl -si -u demo-basic:wrong -d "grant_type=client_credentials" \
  http://localhost:8080/oauth2/token
```

## Configuration

| Property | Default | Meaning |
|---|---|---|
| `oauth2.persistence.repository` | `inmemory` | `inmemory` or `file` |
| `oauth2.file.persistence.clients-file-path` | `./data/clients.json` | Only when the repository is `file` |
| `oauth2.file.persistence.access-tokens-file-path` | `./data/access-tokens.json` | Only when the repository is `file` |
| `oauth2.file.persistence.seed-demo-clients` | `false` | Seed the demo clients into an empty clients file |
| `oauth2.token.format` | `opaque` | `opaque` or `jwt` |
| `oauth2.token.access-token-ttl` | `PT1H` | Token lifetime, ISO-8601 duration |
| `oauth2.jwt.issuer` | `https://localhost:8080` | The `iss` claim |
| `oauth2.jwt.hmac-secret` | dev default | HS256 key, at least 256 bits |

## Next

`authorization_code` and the authorization endpoint · consent · refresh tokens · PKCE (RFC 7636) ·
JPA adapters · client registration · introspection (RFC 7662) and revocation (RFC 7009) ·
server metadata (RFC 8414) · HTTPS enforcement.
