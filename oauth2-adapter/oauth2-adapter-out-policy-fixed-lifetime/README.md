# oauth2-adapter-out-policy-fixed-lifetime

[← Back to the main README](../../README.md)

A single configured access token lifetime, applied to every client.

Package `com.courinha.oauth2.core.adapter.out.policy.fixed`.

`FixedTokenLifetimeAdapter` implements `TokenLifetimePort`, and rejects a non-positive duration at
construction.

The value comes from `oauth2.token.access-token-ttl` (default `PT1H`).

Splitting this out as an adapter rather than hard-coding it keeps the door open for a later
implementation that varies the lifetime per client or per grant.

## Test

```powershell
.\mvnw.cmd -pl oauth2-adapter/oauth2-adapter-out-policy-fixed-lifetime test
```
