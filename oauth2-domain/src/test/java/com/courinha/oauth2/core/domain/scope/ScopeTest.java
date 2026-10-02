package com.courinha.oauth2.core.domain.scope;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * RFC 6749 §3.3: {@code scope-token = 1*( %x21 / %x23-5B / %x5D-7E )}.
 */
class ScopeTest {

    @ParameterizedTest
    @ValueSource(strings = {"read", "Read", "write", "a", "!", "~", "[", "]", "read:write", "a.b.c", "*", "%20"})
    void acceptsTokensWithinTheGrammar(String token) {
        assertThat(new Scope(token).getValue()).isEqualTo(token);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            " ",          // the delimiter itself, x20
            "read write", // x20 inside a token
            "re\"ad",     // x22 is excluded
            "re\\ad",     // x5C is excluded
            "réad",  // non-ASCII
            "read\n",     // control character
            "read\u001F"
    })
    void rejectsTokensOutsideTheGrammar(String token) {
        assertThatThrownBy(() -> new Scope(token))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAnEmptyToken() {
        assertThatThrownBy(() -> new Scope(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");
    }

    @Test
    void tokensAreCaseSensitive() {
        assertThat(new Scope("Read")).isNotEqualTo(new Scope("read"));
    }
}
