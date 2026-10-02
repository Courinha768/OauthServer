package com.courinha.oauth2.core.domain.token;

import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AccessTokenTest {

    private static final ClientId CLIENT_ID = new ClientId("demo");
    private static final Instant ISSUED_AT = Instant.parse("2026-01-01T00:00:00Z");

    private static AccessToken token() {
        return new AccessToken("t-123", CLIENT_ID, ScopeSet.of("read"), TokenType.BEARER,
                ISSUED_AT, ISSUED_AT.plusSeconds(3600));
    }

    /**
     * RFC 6749 §4.4.3 says a refresh token SHOULD NOT accompany a client credentials response.
     * Asserting the record's shape means that if someone later adds a {@code refreshToken}
     * component, this fails loudly instead of the rule quietly eroding.
     */
    @Test
    void modelsNoRefreshToken() {
        Set<String> components = Arrays.stream(AccessToken.class.getRecordComponents())
                .map(RecordComponent::getName)
                .collect(Collectors.toSet());

        assertThat(components).containsExactlyInAnyOrder(
                "value", "clientId", "scopes", "tokenType", "issuedAt", "expiresAt");
    }

    @Test
    void reportsTheLifetimeInWholeSeconds() {
        assertThat(token().expiresInSeconds()).isEqualTo(3600);
    }

    @Test
    void knowsWhenItHasExpired() {
        AccessToken token = token();
        assertThat(token.isExpiredAt(ISSUED_AT.plusSeconds(3599))).isFalse();
        assertThat(token.isExpiredAt(ISSUED_AT.plusSeconds(3600))).isTrue();
    }

    @Test
    void neverRendersTheTokenValueInToString() {
        assertThat(token().toString())
                .doesNotContain("t-123")
                .contains("REDACTED")
                .contains("demo");
    }

    @Test
    void rejectsALifetimeThatDoesNotAdvance() {
        assertThatThrownBy(() -> new AccessToken("t", CLIENT_ID, ScopeSet.empty(), TokenType.BEARER,
                ISSUED_AT, ISSUED_AT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expiresAt must be after issuedAt");
    }

    @Test
    void rejectsABlankValue() {
        assertThatThrownBy(() -> new AccessToken(" ", CLIENT_ID, ScopeSet.empty(), TokenType.BEARER,
                ISSUED_AT, ISSUED_AT.plusSeconds(60)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
