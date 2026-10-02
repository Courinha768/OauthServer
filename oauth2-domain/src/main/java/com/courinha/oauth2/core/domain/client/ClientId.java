package com.courinha.oauth2.core.domain.client;

import java.util.Objects;

/**
 * The identifier a client is issued at registration (RFC 6749 §2.2).
 *
 * <p>A {@code client_id} is not a secret — it travels in authorization URLs and is visible to
 * the resource owner — so it is safe to render in logs and {@code toString()}.
 */
public record ClientId(String value) {

    public ClientId {
        Objects.requireNonNull(value, "value");
        if (value.isBlank()) {
            throw new IllegalArgumentException("client_id must not be blank");
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
