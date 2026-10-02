package com.courinha.oauth2.core.domain.client;

import lombok.Getter;

import java.util.Arrays;
import java.util.Optional;

/**
 * How a client authenticates at the token endpoint (RFC 6749 §2.3).
 *
 * <p>Only the two {@code client_secret_*} methods are modelled: the server issues client
 * passwords and, per §2.3.1, must support HTTP Basic for any client holding one.
 */
@Getter
public enum TokenEndpointAuthMethod {

    /** Credentials in the {@code Authorization} header, form-encoded then Base64 (§2.3.1). */
    CLIENT_SECRET_BASIC("client_secret_basic"),

    /**
     * Credentials in the request body (§2.3.2). Permitted, but not recommended — and §2.3.1
     * forbids sending them in the request URI.
     */
    CLIENT_SECRET_POST("client_secret_post"),

    /** No client authentication; only meaningful for public clients. */
    NONE("none");

    private final String wireValue;

    TokenEndpointAuthMethod(String wireValue) {
        this.wireValue = wireValue;
    }

    public static Optional<TokenEndpointAuthMethod> fromWire(String value) {
        if (value == null) {
            return Optional.empty();
        }
        return Arrays.stream(values())
                .filter(method -> method.wireValue.equals(value))
                .findFirst();
    }

    @Override
    public String toString() {
        return wireValue;
    }
}
