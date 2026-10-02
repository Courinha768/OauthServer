package com.courinha.oauth2.core.domain.client;

import java.util.Objects;

/**
 * A client secret <em>as stored</em> — always a hash, never the plaintext.
 *
 * <p>The type exists to make the distinction impossible to lose: there is no way to hold a
 * registered client's secret in the clear, and {@link #toString()} is redacted so an accidental
 * log statement cannot leak one.
 */
public record SecretHash(String value) {

    public SecretHash {
        Objects.requireNonNull(value, "value");
        if (value.isBlank()) {
            throw new IllegalArgumentException("A secret hash must not be blank");
        }
    }

    /** Always redacted: this is the one type whose contents must never reach a log. */
    @Override
    public String toString() {
        return "SecretHash[REDACTED]";
    }
}
