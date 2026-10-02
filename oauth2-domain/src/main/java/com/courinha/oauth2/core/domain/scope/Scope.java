package com.courinha.oauth2.core.domain.scope;

import java.util.Objects;

/**
 * A single scope token.
 *
 * <p>RFC 6749 §3.3 defines the grammar as
 * {@code scope-token = 1*( %x21 / %x23-5B / %x5D-7E )}. In practice that excludes the space,
 * {@code "} (x22) and {@code \} (x5C), and admits no control characters or non-ASCII. Scope
 * tokens are case-sensitive, so {@code Read} and {@code read} are different scopes.
 */
public record Scope(String value) {

    public Scope {
        Objects.requireNonNull(value, "value");
        requireValidToken(value);
    }

    private static void requireValidToken(String value) {
        if (value.isEmpty()) {
            throw new IllegalArgumentException("A scope token must not be empty");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean permitted = c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E);
            if (!permitted) {
                throw new IllegalArgumentException(
                        "Scope '%s' contains U+%04X, which RFC 6749 §3.3 does not permit"
                                .formatted(value, (int) c));
            }
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
