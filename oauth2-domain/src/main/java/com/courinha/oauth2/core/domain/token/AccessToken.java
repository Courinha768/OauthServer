package com.courinha.oauth2.core.domain.token;

import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.ScopeSet;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * An issued access token.
 *
 * <p>Note what this type does <em>not</em> carry: a refresh token. RFC 6749 §4.4.3 says a
 * refresh token SHOULD NOT accompany the client credentials grant, and the cleanest way to
 * honour that is for the concept to be absent from the model rather than always null. A test
 * asserts the component set below to keep it that way.
 *
 * @param value     the token string handed to the client — the one field that must never be logged
 * @param clientId  the client this token was issued to
 * @param scopes    the scopes actually granted, which may differ from those requested
 * @param tokenType always {@link TokenType#BEARER} today
 * @param issuedAt  when the token was minted
 * @param expiresAt when it stops being valid
 */
public record AccessToken(
        String value,
        ClientId clientId,
        ScopeSet scopes,
        TokenType tokenType,
        Instant issuedAt,
        Instant expiresAt) {

    public AccessToken {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(scopes, "scopes");
        Objects.requireNonNull(tokenType, "tokenType");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");

        if (value.isBlank()) {
            throw new IllegalArgumentException("An access token value must not be blank");
        }
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
        }
    }

    /** The lifetime in whole seconds, as the {@code expires_in} response member reports it. */
    public long expiresInSeconds() {
        return Duration.between(issuedAt, expiresAt).toSeconds();
    }

    public boolean isExpiredAt(Instant instant) {
        return !instant.isBefore(expiresAt);
    }

    /** Redacts the token value so a stray log line cannot hand out a working credential. */
    @Override
    public String toString() {
        return "AccessToken[value=REDACTED, clientId=%s, scopes=%s, tokenType=%s, issuedAt=%s, expiresAt=%s]"
                .formatted(clientId, scopes, tokenType, issuedAt, expiresAt);
    }
}
