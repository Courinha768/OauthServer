package com.courinha.oauth2.core.config;

import com.courinha.oauth2.core.adapter.out.token.jwt.JwtCodec;
import com.courinha.oauth2.core.adapter.out.token.jwt.JwtTokenGenerator;
import com.courinha.oauth2.core.adapter.out.token.opaque.OpaqueTokenGenerator;
import com.courinha.oauth2.core.application.port.out.AccessTokenGenerator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

/**
 * Chooses the token format.
 *
 * <p>Both generator modules are on the classpath, so the decision is made from configuration
 * rather than by which jar was built in. Exactly one {@link AccessTokenGenerator} bean exists at
 * runtime — the two conditions are mutually exclusive.
 */
@Configuration(proxyBeanMethods = false)
public class TokenGeneratorConfiguration {

    @Bean
    @ConditionalOnProperty(name = "oauth2.token.format", havingValue = "opaque", matchIfMissing = true)
    public AccessTokenGenerator opaqueAccessTokenGenerator() {
        return new OpaqueTokenGenerator();
    }

    @Bean
    @ConditionalOnProperty(name = "oauth2.token.format", havingValue = "jwt")
    public AccessTokenGenerator jwtAccessTokenGenerator(JwtProperties properties, ObjectMapper objectMapper) {
        if (properties.getHmacSecret() == null || properties.getHmacSecret().isBlank()) {
            throw new IllegalStateException(
                    "oauth2.token.format=jwt requires oauth2.jwt.hmac-secret (or the OAUTH2_JWT_SECRET "
                            + "environment variable) to be set");
        }
        if (properties.getIssuer() == null || properties.getIssuer().isBlank()) {
            throw new IllegalStateException("oauth2.token.format=jwt requires oauth2.jwt.issuer to be set");
        }

        // The codec rejects a key shorter than 256 bits, so a weak secret fails at startup
        // rather than producing forgeable tokens.
        JwtCodec codec = new JwtCodec(properties.getHmacSecret().getBytes(StandardCharsets.UTF_8), objectMapper);
        return new JwtTokenGenerator(properties.getIssuer(), codec);
    }
}
