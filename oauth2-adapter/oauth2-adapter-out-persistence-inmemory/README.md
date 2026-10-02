# oauth2-adapter-out-persistence-inmemory

[← Back to the main README](../../README.md)

Map-backed repositories. No dependencies beyond `oauth2-application`.

Package `com.courinha.oauth2.core.adapter.out.persistence.inmemory`.

| Class | Implements |
|---|---|
| `InMemoryClientRepository` | `ClientRepository` |
| `InMemoryAccessTokenRepository` | `AccessTokenRepository` |

Both key on a `String` rather than on the domain type. `ClientId` is mutable and derives its
`hashCode` from its value, so using it as a map key would let an in-place mutation orphan an
entry.

`InMemoryClientRepository.add` is deliberately not on the port: registering clients is an
administrative concern no use case performs yet, and keeping the port narrow is what would let a
database adapter expose the same operation through its own interface.

A JPA adapter is planned behind these same ports; because callers only ever see the interface,
that swap touches no domain or application code.

## Test

```powershell
.\mvnw.cmd -pl oauth2-adapter/oauth2-adapter-out-persistence-inmemory test
```
