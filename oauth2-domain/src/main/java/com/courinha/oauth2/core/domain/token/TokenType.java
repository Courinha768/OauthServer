package com.courinha.oauth2.core.domain.token;

import lombok.Getter;

/**
 * The {@code token_type} member of a token response (RFC 6749 §5.1).
 *
 * <p>§5.1 makes the value case-insensitive for clients, so what matters is emitting the
 * canonical spelling that RFC 6750 defines, {@code Bearer}.
 */
@Getter
public enum TokenType {

    BEARER("Bearer");

    private final String wireValue;

    TokenType(String wireValue) {
        this.wireValue = wireValue;
    }

    @Override
    public String toString() {
        return wireValue;
    }
}
