# oauth2-adapter-out-persistence-file

[← Back to the main README](../../README.md)

JSON-file-backed repositories: the same two ports as the in-memory adapter, but the data outlives
the process. Depends on `oauth2-application` and Jackson.

Package `com.courinha.oauth2.core.adapter.out.persistence.file`.

| Class | Implements |
|---|---|
| `FileClientRepository` | `ClientRepository` |
| `FileAccessTokenRepository` | `AccessTokenRepository` |
| `FileConfigs` | `@ConfigurationProperties("oauth2.file.persistence")` |
| `JsonFileStore` | package-private; the shared read/write half of the two above |

Each repository reads its whole file once at construction, keeps the contents in a map, and
rewrites the file on every mutation. That is fine for a registry of clients and for the token
volume this iteration produces; it is not a design that survives a busy token endpoint, which is
what a database adapter is for.

Both key on a `String` rather than on the domain type, for the same reason as the in-memory
adapter: `ClientId` is mutable and derives its `hashCode` from its value.

## Configuration

```properties
oauth2.persistence.repository=file
oauth2.file.persistence.clients-file-path=./data/clients.json
oauth2.file.persistence.access-tokens-file-path=./data/access-tokens.json
oauth2.file.persistence.seed-demo-clients=false
```

Paths may be relative to the working directory. Missing parent directories are created on the
first write. A path that is blank fails at startup with the property name in the message.

### Nothing is seeded by default

Unlike the in-memory adapter, a file-backed server starts with an **empty client registry** — the
file is the operator's source of truth, so writing demo clients with known secrets into it is
something you have to ask for. Set `oauth2.file.persistence.seed-demo-clients=true` to have the
three demo clients written on first run (it only applies when the file is empty). Otherwise every
request gets `invalid_client` until you add a client yourself.

## File format

An array of objects. Instants are ISO-8601 text rather than epoch numbers, so the file stays
readable and does not depend on the JDK's serialization choices.

```json
[
  {
    "id" : "demo-basic",
    "secretHash" : "$2a$10$...",
    "type" : "CONFIDENTIAL",
    "grantTypes" : [ "CLIENT_CREDENTIALS" ],
    "registeredScopes" : [ "read", "write" ],
    "authMethod" : "CLIENT_SECRET_BASIC"
  }
]
```

```json
[
  {
    "value" : "8Kd...",
    "clientId" : "demo-basic",
    "scopes" : [ "read" ],
    "tokenType" : "Bearer",
    "issuedAt" : "2026-10-02T10:15:30.123456789Z",
    "expiresAt" : "2026-10-02T11:15:30.123456789Z"
  }
]
```

The stored shape is a separate record from the domain type, so the file layout never drives the
model.

Enums are written deliberately rather than left to the serializer: `grantTypes` and `authMethod`
use the RFC 6749 wire spellings (`client_credentials`, `client_secret_basic`), `tokenType` uses
RFC 6750's (`Bearer`), and `type` uses the constant name (`CONFIDENTIAL`). Handing that decision
to Jackson would have tied the file format to a framework default and to `toString()` overrides
that live in the domain module — so renaming a constant for readability would silently change the
format and orphan every file already written.

A file the adapter cannot parse — malformed JSON, or an unknown enum value — fails loudly at
startup rather than being treated as an empty store. Silently dropping clients would turn a typo
into a stream of `invalid_client` responses.

## Security

**The access token file holds live credentials in the clear.** An issued token is usable by
anyone who can read it, so the file needs the same care as a password store: restrictive
permissions, no backups to untrusted places, and never committed to version control — `/data/` is
already in `.gitignore` for that reason. A production deployment should prefer a database with an
encrypted volume.

Each data file is created owner-only (`rw-------`) on platforms with POSIX permissions. An
existing file is left exactly as it is, since a deployment may have a deliberate reason for wider
access; the default is safe, but it is not a guarantee about a file someone else created. On
Windows the restriction is a no-op.

Client secrets are only ever stored as their BCrypt hash, because the domain model never holds
the plaintext.

## Test

```powershell
.\mvnw.cmd -pl oauth2-adapter/oauth2-adapter-out-persistence-file test
```
