package com.courinha.oauth2.core.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings for the HS256 JWT generator, used only when {@code oauth2.token.format=jwt}.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@ConfigurationProperties(prefix = "oauth2.jwt")
public class JwtProperties {

    /** The {@code iss} claim. */
    private String issuer;

    /** The shared secret; must be at least 256 bits, enforced when the codec is built. */
    private String hmacSecret;
}
