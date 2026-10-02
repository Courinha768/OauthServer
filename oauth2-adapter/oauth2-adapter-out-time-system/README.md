# oauth2-adapter-out-time-system

[← Back to the main README](../../README.md)

The system clock.

Package `com.courinha.oauth2.core.adapter.out.time.system`.

`SystemClockAdapter` implements `ClockPort`.

This is the **only** class in the codebase permitted to read the wall clock, and an ArchUnit rule
in `oauth2-boot` enforces that. Everything else takes the time as a parameter, which is what keeps
token-expiry assertions deterministic instead of eventually flaky.

## Test

```powershell
.\mvnw.cmd -pl oauth2-adapter/oauth2-adapter-out-time-system test
```
