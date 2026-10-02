package com.courinha.oauth2.core.adapter.out.token.jwt;

import com.courinha.oauth2.core.application.port.out.AccessTokenGenerator;
import com.courinha.oauth2.core.application.port.out.TokenGenerationRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Mints a self-contained HS256 JWT (RFC 7519) instead of an opaque string.
 *
 * <p>A resource server can validate this without calling back here. The trade-off is that
 * revocation stops being a deletion, which is why the application service still stores every
 * token even when this generator is selected.
 *
 * <p>Claim order is fixed via {@link LinkedHashMap} so the encoded output is stable for a given
 * input, which keeps tests deterministic.
 */
public final class JwtTokenGenerator implements AccessTokenGenerator {

    private final String issuer;
    private final JwtCodec codec;

    public JwtTokenGenerator(String issuer, JwtCodec codec) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.codec = Objects.requireNonNull(codec, "codec");
    }

    @Override
    public String generate(TokenGenerationRequest request) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", request.getClientId().getValue());
        claims.put("client_id", request.getClientId().getValue());
        claims.put("scope", request.getScopes().asSpaceDelimited());
        claims.put("iat", request.getIssuedAt().getEpochSecond());
        claims.put("exp", request.getExpiresAt().getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        // No 'aud': there is no resource server registered yet, and inventing an audience would
        // be worse than omitting one.

        return codec.encode(header, claims);
    }
}
