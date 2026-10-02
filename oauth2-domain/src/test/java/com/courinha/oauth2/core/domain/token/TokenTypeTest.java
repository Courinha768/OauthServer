package com.courinha.oauth2.core.domain.token;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenTypeTest {

    @Test
    void emitsTheCanonicalSpellingRfc6750Defines() {
        assertThat(TokenType.BEARER.getWireValue()).isEqualTo("Bearer");
        assertThat(TokenType.BEARER).hasToString("Bearer");
    }

    @Test
    void resolvesTheWireSpellingBackToTheEnum() {
        assertThat(TokenType.fromWire("Bearer")).contains(TokenType.BEARER);
    }

    @Test
    void doesNotResolveAnUnrecognisedOrAbsentValue() {
        assertThat(TokenType.fromWire("BEARER")).isEmpty();
        assertThat(TokenType.fromWire("MAC")).isEmpty();
        assertThat(TokenType.fromWire(null)).isEmpty();
    }
}
