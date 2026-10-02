package com.courinha.oauth2.core.domain.error;

/**
 * Signals that a request must be answered with an RFC 6749 §5.2 error response.
 *
 * <p>The domain raises this; only the web adapter decides what HTTP status and headers it becomes.
 */
public class OAuth2Exception extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient OAuth2Error error;

    public OAuth2Exception(OAuth2Error error) {
        super(error.code().wireValue()
                + (error.description() == null ? "" : ": " + error.description()));
        this.error = error;
    }

    public OAuth2Error error() {
        return error;
    }

    public OAuth2ErrorCode code() {
        return error.code();
    }

    /** The request is malformed, or missing a required parameter. */
    public static OAuth2Exception invalidRequest(String description) {
        return new OAuth2Exception(OAuth2Error.of(OAuth2ErrorCode.INVALID_REQUEST, description));
    }

    /** The request carries a parameter more than once, which §3.2 forbids. */
    public static OAuth2Exception duplicateParameter(String name) {
        return invalidRequest("Parameter '" + name + "' must not be included more than once");
    }

    /**
     * Client authentication failed.
     *
     * <p>The description is deliberately identical whether the client is unknown or the secret is
     * wrong. Distinguishing the two would let an unauthenticated caller enumerate valid
     * {@code client_id}s, so every authentication failure funnels through this one factory.
     */
    public static OAuth2Exception invalidClient() {
        return new OAuth2Exception(
                OAuth2Error.of(OAuth2ErrorCode.INVALID_CLIENT, "Client authentication failed"));
    }

    /** The server does not recognise, or does not implement, the requested grant type. */
    public static OAuth2Exception unsupportedGrantType() {
        return new OAuth2Exception(OAuth2Error.of(OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE,
                "The authorization server does not support this grant type"));
    }

    /** The client authenticated, but is not permitted to use this grant type. */
    public static OAuth2Exception unauthorizedClient() {
        return new OAuth2Exception(OAuth2Error.of(OAuth2ErrorCode.UNAUTHORIZED_CLIENT,
                "The authenticated client is not authorized to use this grant type"));
    }

    /** The requested scope is unknown, malformed, or exceeds the client's registered scopes. */
    public static OAuth2Exception invalidScope() {
        return new OAuth2Exception(OAuth2Error.of(OAuth2ErrorCode.INVALID_SCOPE,
                "The requested scope is invalid, unknown, or exceeds the scope granted to the client"));
    }
}
