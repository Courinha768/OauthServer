package com.courinha.oauth2.core.application.port.out;

import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

/**
 * Everything a token generator needs to mint a value, and nothing more.
 */
@Data
@NoArgsConstructor
public class TokenGenerationRequest {

    /** The subject the token is issued to. */
    private ClientId clientId;

    /** The scopes actually granted. */
    private ScopeSet scopes;

    /** The {@code iat} instant. */
    private Instant issuedAt;

    /** The {@code exp} instant. */
    private Instant expiresAt;

    @Builder
    public TokenGenerationRequest(ClientId clientId, ScopeSet scopes, Instant issuedAt, Instant expiresAt) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(scopes, "scopes");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");

        this.clientId = clientId;
        this.scopes = scopes;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }
}
