package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.domain.error.OAuth2ErrorCode;
import org.springframework.http.HttpStatus;

import java.util.Optional;

/**
 * Maps a domain error code onto its HTTP representation.
 *
 * <p>This is the boundary the domain deliberately does not cross: nothing inside the hexagon
 * knows what a status code is.
 */
public final class OAuth2ErrorHttpMapper {

    /** RFC 6749 §5.2 shows no realm, but §2.3.1 requires TLS and a challenge helps clients. */
    private static final String CHALLENGE = "Basic realm=\"oauth2\", charset=\"UTF-8\"";

    private OAuth2ErrorHttpMapper() {
    }

    /**
     * RFC 6749 §5.2: errors are {@code 400}, with one exception. When the client attempted to
     * authenticate through the {@code Authorization} header, {@code invalid_client} MUST be a
     * {@code 401} carrying a matching {@code WWW-Authenticate}. For credentials in the body,
     * {@code 400} is correct and no challenge is sent.
     *
     * <p>The switch is exhaustive over {@link OAuth2ErrorCode} with no default, so adding a code
     * without deciding its status is a compile error rather than a silent {@code 400}.
     */
    public static HttpStatus statusFor(OAuth2ErrorCode code, boolean attemptedAuthorizationHeader) {
        return switch (code) {
            case INVALID_CLIENT -> attemptedAuthorizationHeader
                    ? HttpStatus.UNAUTHORIZED
                    : HttpStatus.BAD_REQUEST;
            case INVALID_REQUEST,
                 INVALID_GRANT,
                 UNAUTHORIZED_CLIENT,
                 UNSUPPORTED_GRANT_TYPE,
                 INVALID_SCOPE -> HttpStatus.BAD_REQUEST;
        };
    }

    /** The {@code WWW-Authenticate} value, present only for the {@code 401} case above. */
    public static Optional<String> challengeFor(OAuth2ErrorCode code, boolean attemptedAuthorizationHeader) {
        boolean challenged = code == OAuth2ErrorCode.INVALID_CLIENT && attemptedAuthorizationHeader;
        return challenged ? Optional.of(CHALLENGE) : Optional.empty();
    }
}
