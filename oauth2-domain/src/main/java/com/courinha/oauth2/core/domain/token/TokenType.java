package com.courinha.oauth2.core.domain.token;

import lombok.Getter;

import java.util.Arrays;
import java.util.Optional;

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

    /**
     * Resolves a stored or transmitted {@code token_type} back to the enum.
     *
     * <p>Matching is done on the wire spelling rather than on the constant name, so a persisted
     * value stays the one RFC 6750 defines even if the constant is ever renamed.
     */
    public static Optional<TokenType> fromWire(String value) {
        if (value == null) {
            return Optional.empty();
        }
        return Arrays.stream(values())
                .filter(tokenType -> tokenType.wireValue.equals(value))
                .findFirst();
    }

    @Override
    public String toString() {
        return wireValue;
    }
}
