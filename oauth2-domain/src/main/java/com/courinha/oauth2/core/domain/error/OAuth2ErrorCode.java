package com.courinha.oauth2.core.domain.error;

import lombok.Getter;

/**
 * The error codes RFC 6749 §5.2 defines for the token endpoint.
 *
 * <p>Note what is deliberately absent. {@code server_error} and {@code temporarily_unavailable}
 * look like they belong here but do not: RFC 6749 defines them in §4.1.2.1 for the
 * <em>authorization</em> endpoint only, and §5.2 does not list them for the token endpoint. An
 * unexpected internal failure at {@code /token} is not an OAuth error and must surface as a
 * plain HTTP 500 rather than a fabricated error body.
 *
 * <p>This type carries no HTTP status. Mapping a code to a status code and headers is the web
 * adapter's job, so the domain stays free of transport concerns.
 */
@Getter
public enum OAuth2ErrorCode {

    /** The request is missing a required parameter, or is otherwise malformed. §5.2 */
    INVALID_REQUEST("invalid_request"),

    /** Client authentication failed: unknown client, bad secret, or no credentials. §5.2 */
    INVALID_CLIENT("invalid_client"),

    /** The grant or refresh token is invalid, expired, or revoked. §5.2 */
    INVALID_GRANT("invalid_grant"),

    /** The authenticated client is not allowed to use this grant type. §5.2 */
    UNAUTHORIZED_CLIENT("unauthorized_client"),

    /** The authorization server does not support this grant type. §5.2 */
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),

    /** The requested scope is invalid, unknown, malformed, or exceeds what was granted. §5.2 */
    INVALID_SCOPE("invalid_scope");

    /** The literal value that appears as the {@code error} member of the JSON response body. */
    private final String wireValue;

    OAuth2ErrorCode(String wireValue) {
        this.wireValue = wireValue;
    }
}
