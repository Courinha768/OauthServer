# oauth2-adapter-out-secret-bcrypt

[← Back to the main README](../../README.md)

BCrypt client secret hashing.

Package `com.courinha.oauth2.core.adapter.out.secret.bcrypt`.

`BCryptClientSecretHasher` implements `ClientSecretHasher`, backed by the standalone
`spring-security-crypto` artifact — the crypto utilities only, without pulling in Spring Security
proper.

BCrypt is deliberately slow and salts each hash, so a stolen client table does not yield reusable
secrets.

Secrets are only ever stored as a `SecretHash`, a domain type that cannot hold plaintext and
redacts itself in `toString()`. Hashing happens at registration; authentication only ever
compares.

## Test

```powershell
.\mvnw.cmd -pl oauth2-adapter/oauth2-adapter-out-secret-bcrypt test
```
