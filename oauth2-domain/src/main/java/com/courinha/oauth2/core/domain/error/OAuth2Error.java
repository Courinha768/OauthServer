package com.courinha.oauth2.core.domain.error;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Objects;

/**
 * An RFC 6749 §5.2 error response, minus its transport. {@code description} and {@code errorUri}
 * are optional.
 */
@Data
@NoArgsConstructor
@Builder
public class OAuth2Error {

    private OAuth2ErrorCode code;

    /** Human-readable detail, or {@code null}. */
    private String description;

    /** A URI identifying the error, or {@code null}. */
    private String errorUri;

    /**
     * Validates on construction, so an error can never be built that the RFC forbids sending.
     * Note that the generated setters assign directly and do not re-check; the constructor is
     * the validated entry point.
     */
    @Builder
    public OAuth2Error(OAuth2ErrorCode code, String description, String errorUri) {
        Objects.requireNonNull(code, "code");
        if (description != null) {
            requirePermittedCharacters(description, true, "error_description");
        }
        if (errorUri != null) {
            requirePermittedCharacters(errorUri, false, "error_uri");
        }
        this.code = code;
        this.description = description;
        this.errorUri = errorUri;
    }

    public static OAuth2Error of(OAuth2ErrorCode code) {
        return new OAuth2Error(code, null, null);
    }

    public static OAuth2Error of(OAuth2ErrorCode code, String description) {
        return new OAuth2Error(code, description, null);
    }

    /**
     * RFC 6749 §5.2 constrains the characters these values may contain, so that an error
     * response can never smuggle control characters or non-ASCII into a client's logs.
     *
     * <p>{@code error} and {@code error_description} allow {@code %x20-21 / %x23-5B / %x5D-7E};
     * {@code error_uri} allows the same set without the space.
     */
    private static void requirePermittedCharacters(String value, boolean allowSpace, String field) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean permitted = allowSpace
                    ? (c >= 0x20 && c <= 0x21) || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)
                    : c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E);
            if (!permitted) {
                throw new IllegalArgumentException(
                        "%s contains U+%04X, which RFC 6749 §5.2 does not permit".formatted(field, (int) c));
            }
        }
    }
}
