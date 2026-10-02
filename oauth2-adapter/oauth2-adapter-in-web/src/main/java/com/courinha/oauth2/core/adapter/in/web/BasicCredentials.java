package com.courinha.oauth2.core.adapter.in.web;

/**
 * Credentials recovered from an {@code Authorization: Basic} header.
 *
 * @param clientId     the decoded client identifier
 * @param clientSecret the decoded secret; may be empty, which §2.3.1 permits
 */
public record BasicCredentials(String clientId, String clientSecret) {

    /** Redacts the secret: this object is built from a header and must not be logged whole. */
    @Override
    public String toString() {
        return "BasicCredentials[clientId=%s, clientSecret=REDACTED]".formatted(clientId);
    }
}
