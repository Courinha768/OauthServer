package com.courinha.oauth2.core.application.port.out;

import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.ScopeSet;

import java.time.Instant;
import java.util.Objects;

/**
 * Everything a token generator needs to mint a value, and nothing more.
 *
 * @param clientId  the subject the token is issued to
 * @param scopes    the scopes actually granted
 * @param issuedAt  the {@code iat} instant
 * @param expiresAt the {@code exp} instant
 */
public record TokenGenerationRequest(
        ClientId clientId,
        ScopeSet scopes,
        Instant issuedAt,
        Instant expiresAt) {

    public TokenGenerationRequest {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(scopes, "scopes");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
