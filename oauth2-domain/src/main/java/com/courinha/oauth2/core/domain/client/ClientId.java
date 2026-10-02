package com.courinha.oauth2.core.domain.client;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Objects;

/**
 * The identifier a client is issued at registration (RFC 6749 §2.2).
 *
 * <p>A {@code client_id} is not a secret — it travels in authorization URLs and is visible to
 * the resource owner — so it is safe to render in logs.
 *
 * <p>Being mutable, this type must never be used as a map key: its {@code hashCode} derives from
 * {@code value}, so mutating an instance already inside a {@code HashMap} would make it
 * unreachable. The repositories key on the {@code String} instead.
 */
@Data
@NoArgsConstructor
public class ClientId {

    private String value;

    /** Validates on construction; the generated setter assigns directly, as Lombok setters do. */
    @Builder
    public ClientId(String value) {
        Objects.requireNonNull(value, "value");
        if (value.isBlank()) {
            throw new IllegalArgumentException("client_id must not be blank");
        }
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
