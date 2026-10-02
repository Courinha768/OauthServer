package com.courinha.oauth2.core.domain.token;

import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
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
        return AccessToken.builder()
                .value("t-123")
                .clientId(CLIENT_ID)
                .scopes(ScopeSet.of("read"))
                .tokenType(TokenType.BEARER)
                .issuedAt(ISSUED_AT)
                .expiresAt(ISSUED_AT.plusSeconds(3600))
                .build();
    }

    /**
     * RFC 6749 §4.4.3 says a refresh token SHOULD NOT accompany a client credentials response.
     * Asserting the field set means that if someone later adds a {@code refreshToken} field,
     * this fails loudly instead of the rule quietly eroding.
     */
    @Test
    void modelsNoRefreshToken() {
        Set<String> fields = Arrays.stream(AccessToken.class.getDeclaredFields())
                .filter(field -> !field.isSynthetic())
                .filter(field -> !Modifier.isStatic(field.getModifiers()))
                .map(Field::getName)
                .collect(Collectors.toSet());

        assertThat(fields).containsExactlyInAnyOrder(
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
    void isComparableByValue() {
        assertThat(token()).isEqualTo(token());
        assertThat(token()).hasSameHashCodeAs(token());
    }

    @Test
    void rejectsALifetimeThatDoesNotAdvance() {
        assertThatThrownBy(() -> AccessToken.builder()
                .value("t")
                .clientId(CLIENT_ID)
                .scopes(ScopeSet.empty())
                .tokenType(TokenType.BEARER)
                .issuedAt(ISSUED_AT)
                .expiresAt(ISSUED_AT)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expiresAt must be after issuedAt");
    }

    @Test
    void rejectsABlankValue() {
        assertThatThrownBy(() -> AccessToken.builder()
                .value(" ")
                .clientId(CLIENT_ID)
                .scopes(ScopeSet.empty())
                .tokenType(TokenType.BEARER)
                .issuedAt(ISSUED_AT)
                .expiresAt(ISSUED_AT.plusSeconds(60))
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
