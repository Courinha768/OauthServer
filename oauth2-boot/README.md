# oauth2-boot

[← Back to the main README](../README.md)

The Spring Boot composition root: wires adapters to ports and starts the server.

This is the only module that is a runnable application, and the only one whose tests have Spring on
the classpath. It depends on every adapter, so it is where the mix-and-match decision is made.

| Class | Responsibility |
|---|---|
| `Oauth2CoreApplication` | The `@SpringBootApplication`. |
| `AdapterWiringConfiguration` | Binds driven adapters to the ports they implement, selecting persistence from `oauth2.persistence.repository`. |
| `TokenGeneratorConfiguration` | Chooses the token format from configuration. |
| `UseCaseWiringConfiguration` | Assembles the use case from its ports. |
| `ClientSeedConfiguration` | Seeds the demo clients. |
| `TokenProperties`, `JwtProperties` | Bound from `application.properties`. |

`Oauth2CoreApplication` is deliberately kept in `com.courinha.oauth2.core` rather than a `boot`
subpackage: component scanning starts there, and the adapters live under
`com.courinha.oauth2.core.adapter`. Moving it down a level would silently stop the controller from
being registered and every request would 404 with a green build.

Each `@Bean` returns the **port** type, not the adapter class, so nothing downstream can depend on
which implementation was chosen. Both token generator modules are on the classpath and selected by
`oauth2.token.format`, so the format is a runtime choice rather than a build-time one.

## Configuration

```properties
oauth2.persistence.repository=inmemory   # or file
oauth2.file.persistence.clients-file-path=./data/clients.json
oauth2.file.persistence.access-tokens-file-path=./data/access-tokens.json
oauth2.file.persistence.seed-demo-clients=false

oauth2.token.format=opaque            # or jwt
oauth2.token.access-token-ttl=PT1H
oauth2.jwt.issuer=https://localhost:8080
oauth2.jwt.hmac-secret=${OAUTH2_JWT_SECRET:dev-only-insecure-secret-change-me-32b}
```

Persistence is a runtime choice for the same reason the token format is: both adapters are on the
classpath and `oauth2.persistence.repository` picks between them. The demo clients are seeded into
the in-memory store automatically, but into the file store only when
`oauth2.file.persistence.seed-demo-clients=true`, since that file is the operator's source of
truth — see
[out-persistence-file](../oauth2-adapter/oauth2-adapter-out-persistence-file/README.md).

The `hmac-secret` default is for development only. Supply `OAUTH2_JWT_SECRET` in any real
deployment; it must be at least 256 bits, which the codec enforces at startup.

## Run

From the repository root:

```powershell
$env:JAVA_HOME = "C:\Users\anton\.jdks\openjdk-25.0.1"
.\mvnw.cmd -pl oauth2-boot spring-boot:run
```

Or with the JWT format:

```powershell
.\mvnw.cmd -pl oauth2-boot spring-boot:run "-Dspring-boot.run.arguments=--oauth2.token.format=jwt"
```

## Test

From the repository root:

```powershell
.\mvnw.cmd -pl oauth2-boot test
```

Two layers: an end-to-end suite against the real wiring and the seeded clients, run for both token
formats, and `HexagonalArchitectureTest`, which asserts the dependency direction and that only the
clock adapter reads the wall clock.
