package com.courinha.oauth2.core.domain.client;

import java.util.Arrays;
import java.util.Optional;

/**
 * The grant types defined by RFC 6749 §4, plus the refresh token grant (§6) which reuses the
 * same wire parameter.
 *
 * <p>Only {@link #CLIENT_CREDENTIALS} is implemented so far; the others are modelled because
 * client registrations name them, and a registration must be able to express a grant the server
 * will later refuse with {@code unauthorized_client} rather than fail to parse.
 */
public enum GrantType {

    AUTHORIZATION_CODE("authorization_code"),
    IMPLICIT("implicit"),
    PASSWORD("password"),
    CLIENT_CREDENTIALS("client_credentials"),
    REFRESH_TOKEN("refresh_token");

    private final String wireValue;

    GrantType(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    /**
     * Resolves the {@code grant_type} request parameter.
     *
     * <p>Matching is exact and case-sensitive, as RFC 6749 §4.4.2 requires. An unrecognised
     * value yields {@link Optional#empty()} rather than throwing, so the caller can decide
     * whether that means {@code unsupported_grant_type} or {@code invalid_request}.
     */
    public static Optional<GrantType> fromWire(String value) {
        if (value == null) {
            return Optional.empty();
        }
        return Arrays.stream(values())
                .filter(grantType -> grantType.wireValue.equals(value))
                .findFirst();
    }

    @Override
    public String toString() {
        return wireValue;
    }
}
