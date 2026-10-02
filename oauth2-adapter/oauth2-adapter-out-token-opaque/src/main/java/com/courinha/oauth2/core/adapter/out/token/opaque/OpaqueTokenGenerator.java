package com.courinha.oauth2.core.adapter.out.token.opaque;

import com.courinha.oauth2.core.application.port.out.AccessTokenGenerator;
import com.courinha.oauth2.core.application.port.out.TokenGenerationRequest;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Mints an opaque token: 256 bits from a CSPRNG, Base64 URL encoded.
 *
 * <p>RFC 6749 §1.4 leaves the token format to the server, and §10.10 requires the value to be
 * unpredictable. The token carries no meaning of its own — it is only a key into
 * {@code AccessTokenRepository}, which is what makes revocation a deletion.
 */
public final class OpaqueTokenGenerator implements AccessTokenGenerator {

    /** 256 bits, the same floor RFC 7518 §3.2 sets for an HS256 key, for the same reason. */
    private static final int TOKEN_BYTES = 32;

    private final SecureRandom random;

    public OpaqueTokenGenerator() {
        this(new SecureRandom());
    }

    public OpaqueTokenGenerator(SecureRandom random) {
        this.random = random;
    }

    @Override
    public String generate(TokenGenerationRequest request) {
        byte[] value = new byte[TOKEN_BYTES];
        random.nextBytes(value);
        // withoutPadding: '=' is not URL-safe and would need escaping in a query string.
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
