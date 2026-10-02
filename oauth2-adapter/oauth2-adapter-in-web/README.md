# oauth2-adapter-in-web

[← Back to the main README](../../README.md)

The driving adapter: the RFC 6749 token endpoint, over plain Spring WebMVC.

Package `com.courinha.oauth2.core.adapter.in.web`. There is no Spring Security — client
authentication is parsed and enforced here.

| Class | Responsibility |
|---|---|
| `TokenEndpointController` | `POST /oauth2/token`. Binds the request, delegates, renders the result. |
| `TokenRequestParser` | Turns the HTTP shape into a `ClientCredentialsCommand`. |
| `BasicAuthHeaderParser` | Decodes `Authorization: Basic` per §2.3.1 and Appendix B. |
| `OAuth2ErrorHttpMapper` | Maps a domain error code onto a status and a challenge. |
| `OAuth2ExceptionHandler` | Renders an `OAuth2Exception` as a §5.2 error response. |
| `TokenResponseBody`, `ErrorResponseBody` | The wire representations. |
| `BasicCredentials` | Decoded credentials, with the secret redacted in `toString()`. |

## Details that matter

- Parameters bind as a `MultiValueMap`, not individual `@RequestParam` values. Spring silently
  collapses repeated parameters otherwise, and §3.2 forbids any parameter appearing twice.
- Appendix B credentials are form-urlencoded *before* being Base64'd, so decoding undoes two
  layers: Base64, then split on the first colon, then form-decode each half. Skipping the last
  step corrupts any secret containing `+`, `%`, `&`, a space, or a non-ASCII character.
- The mapper's `switch` is exhaustive over `OAuth2ErrorCode` with no default, so adding a code
  without deciding its status is a compile error.
- `invalid_client` is 401 with a `WWW-Authenticate` header only when the request carried an
  `Authorization` header. Body credentials get a 400 and no challenge.
- No `consumes` restriction is declared: a non-form request simply yields no parameters, and the
  missing `grant_type` becomes the `invalid_request` §5.2 wants rather than Spring's own 415.
- Token and error responses carry `Cache-Control: no-store` and `Pragma: no-cache`, as §5.1
  requires.

## Test

```powershell
.\mvnw.cmd -pl oauth2-adapter/oauth2-adapter-in-web test
```
