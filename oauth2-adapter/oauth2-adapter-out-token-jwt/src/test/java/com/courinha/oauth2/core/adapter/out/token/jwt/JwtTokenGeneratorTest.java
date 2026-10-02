package com.courinha.oauth2.core.adapter.out.token.jwt;

import com.courinha.oauth2.core.application.port.out.TokenGenerationRequest;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenGeneratorTest {

    private static final String ISSUER = "https://issuer.example";
    private static final byte[] KEY = "a-test-key-that-is-at-least-32-bytes-long".getBytes(StandardCharsets.UTF_8);
    private static final Instant ISSUED_AT = Instant.parse("2026-01-01T00:00:00Z");

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtCodec codec = new JwtCodec(KEY, objectMapper);
    private final JwtTokenGenerator generator = new JwtTokenGenerator(ISSUER, codec);

    private static TokenGenerationRequest request() {
        return TokenGenerationRequest.builder()
                .clientId(new ClientId("demo"))
                .scopes(ScopeSet.of("read", "write"))
                .issuedAt(ISSUED_AT)
                .expiresAt(ISSUED_AT.plusSeconds(3600))
                .build();
    }

    private JsonNode decodeSegment(String token, int index) {
        String segment = token.split("\\.")[index];
        return objectMapper.readTree(Base64.getUrlDecoder().decode(segment));
    }

    @Test
    void producesThreeDotSeparatedSegments() {
        assertThat(generator.generate(request()).split("\\.")).hasSize(3);
    }

    @Test
    void usesTheUrlSafeAlphabetWithoutPadding() {
        String token = generator.generate(request());

        // '=' would need escaping in a query string; '+' and '/' are not URL-safe at all.
        assertThat(token).doesNotContain("=", "+", "/");
        assertThat(token).matches("[A-Za-z0-9_.-]+");
    }

    @Test
    void emitsTheExpectedHeader() {
        JsonNode header = decodeSegment(generator.generate(request()), 0);

        assertThat(header.get("alg").asString()).isEqualTo("HS256");
        assertThat(header.get("typ").asString()).isEqualTo("JWT");
    }

    @Test
    void emitsTheExpectedClaims() {
        JsonNode claims = decodeSegment(generator.generate(request()), 1);

        assertThat(claims.get("iss").asString()).isEqualTo(ISSUER);
        assertThat(claims.get("sub").asString()).isEqualTo("demo");
        assertThat(claims.get("client_id").asString()).isEqualTo("demo");
        assertThat(claims.get("scope").asString()).isEqualTo("read write");
        assertThat(claims.get("iat").asLong()).isEqualTo(ISSUED_AT.getEpochSecond());
        assertThat(claims.get("exp").asLong()).isEqualTo(ISSUED_AT.plusSeconds(3600).getEpochSecond());
        assertThat(claims.get("jti").asString()).isNotBlank();
    }

    @Test
    void carriesNoAudienceBecauseNoResourceServerIsRegisteredYet() {
        assertThat(decodeSegment(generator.generate(request()), 1).has("aud")).isFalse();
    }

    /** Recomputes the HMAC from scratch, so a bug in the codec cannot mask itself. */
    @Test
    void signsTheEncodedSegmentsWithHmacSha256() throws Exception {
        String token = generator.generate(request());
        String[] parts = token.split("\\.");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
        byte[] expected = mac.doFinal((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));

        assertThat(Base64.getUrlDecoder().decode(parts[2])).isEqualTo(expected);
    }

    @Test
    void verifiesItsOwnOutput() {
        assertThat(codec.verify(generator.generate(request()))).isTrue();
    }

    @Test
    void rejectsATamperedPayload() {
        String token = generator.generate(request());
        String[] parts = token.split("\\.");

        // Flip one character of the payload, leaving the signature untouched.
        char[] payload = parts[1].toCharArray();
        payload[0] = payload[0] == 'A' ? 'B' : 'A';
        String tampered = parts[0] + "." + new String(payload) + "." + parts[2];

        assertThat(codec.verify(tampered)).isFalse();
    }

    @Test
    void rejectsASignatureFromADifferentKey() {
        JwtCodec otherKeyCodec = new JwtCodec(
                "a-completely-different-key-of-32-bytes!!".getBytes(StandardCharsets.UTF_8), objectMapper);

        assertThat(otherKeyCodec.verify(generator.generate(request()))).isFalse();
    }

    @Test
    void rejectsAMalformedToken() {
        assertThat(codec.verify("not-a-jwt")).isFalse();
        assertThat(codec.verify("only.two")).isFalse();
    }

    @Test
    void givesEachTokenAUniqueIdentifier() {
        String first = decodeSegment(generator.generate(request()), 1).get("jti").asString();
        String second = decodeSegment(generator.generate(request()), 1).get("jti").asString();

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void refusesAKeyShorterThan256Bits() {
        assertThatThrownBy(() -> new JwtCodec("too-short".getBytes(StandardCharsets.UTF_8), objectMapper))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 32 bytes");
    }
}
