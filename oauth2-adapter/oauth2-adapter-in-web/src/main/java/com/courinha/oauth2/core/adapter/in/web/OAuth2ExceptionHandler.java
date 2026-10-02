package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.domain.error.OAuth2Error;
import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Renders an {@link OAuth2Exception} as an RFC 6749 §5.2 error response.
 *
 * <p>The cache headers matter as much as the status code: §5.1 requires them on any response
 * carrying tokens or credentials, and an error response can echo enough of a request to be
 * worth keeping out of a shared cache.
 *
 * <p>An exception that is <em>not</em> an {@code OAuth2Exception} is deliberately not handled
 * here. There is no {@code server_error} at the token endpoint — §5.2 does not define one — so
 * an unexpected failure surfaces as a plain HTTP 500 rather than a fabricated OAuth error body.
 */
@RestControllerAdvice
public class OAuth2ExceptionHandler {

    @ExceptionHandler(OAuth2Exception.class)
    public ResponseEntity<ErrorResponseBody> handle(OAuth2Exception exception, HttpServletRequest request) {
        OAuth2Error error = exception.getError();
        boolean attemptedAuthorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION) != null;

        ResponseEntity.BodyBuilder response = ResponseEntity
                .status(OAuth2ErrorHttpMapper.statusFor(error.getCode(), attemptedAuthorizationHeader))
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache");

        OAuth2ErrorHttpMapper.challengeFor(error.getCode(), attemptedAuthorizationHeader)
                .ifPresent(challenge -> response.header(HttpHeaders.WWW_AUTHENTICATE, challenge));

        return response.body(ErrorResponseBody.from(error));
    }
}
