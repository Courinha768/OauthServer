package com.courinha.oauth2.core.adapter.out.token.opaque;

import com.courinha.oauth2.core.application.port.out.TokenGenerationRequest;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class OpaqueTokenGeneratorTest {

    private final OpaqueTokenGenerator generator = new OpaqueTokenGenerator();

    private static TokenGenerationRequest request() {
        return TokenGenerationRequest.builder()
                .clientId(new ClientId("demo"))
                .scopes(ScopeSet.of("read"))
                .issuedAt(Instant.parse("2026-01-01T00:00:00Z"))
                .expiresAt(Instant.parse("2026-01-01T01:00:00Z"))
                .build();
    }

    @Test
    void encodes256BitsAsUnpaddedBase64Url() {
        String token = generator.generate(request());

        // 32 bytes -> 43 base64url characters with the padding removed.
        assertThat(token).hasSize(43);
        assertThat(token).matches("[A-Za-z0-9_-]+");
        assertThat(token).doesNotContain("=", "+", "/");
    }

    @Test
    void isUnpredictableAcrossManyDraws() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 10_000; i++) {
            seen.add(generator.generate(request()));
        }

        assertThat(seen).hasSize(10_000);
    }

    @Test
    void ignoresTheRequestWhenGenerating() {
        // An opaque token carries no claims; it is only a key into the token store.
        String first = generator.generate(request());
        String second = generator.generate(request());

        assertThat(first).isNotEqualTo(second);
    }
}
