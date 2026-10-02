package com.courinha.oauth2.core.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Token issuance settings.
 *
 * <p>Bound as a JavaBean rather than by constructor, which is why it needs a no-arg constructor
 * and setters — both supplied by Lombok.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@ConfigurationProperties(prefix = "oauth2.token")
public class TokenProperties {

    /** Which {@code AccessTokenGenerator} adapter to activate. */
    private TokenFormat format;

    /** How long an issued token stays valid. */
    private Duration accessTokenTtl;

    /**
     * Binding is by name and case-insensitive, so an unrecognised value fails application
     * startup rather than silently falling back to a default.
     */
    public enum TokenFormat {
        OPAQUE,
        JWT
    }
}
