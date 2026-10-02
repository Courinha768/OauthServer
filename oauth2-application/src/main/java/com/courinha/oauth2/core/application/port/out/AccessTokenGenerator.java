package com.courinha.oauth2.core.application.port.out;

/**
 * Mints the token string handed to the client.
 *
 * <p>RFC 6749 mandates no particular format, so this is a genuine implementation choice with
 * two adapters: an opaque random value, and a self-contained HS256 JWT. Both return a plain
 * string, which is why the application layer never needs to know which one is in use.
 */
@FunctionalInterface
public interface AccessTokenGenerator {

    String generate(TokenGenerationRequest request);
}
