package com.courinha.oauth2.core.domain.scope;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ScopeSetTest {

    @Test
    void parsesSpaceDelimitedScopes() {
        assertThat(ScopeSet.fromSpaceDelimited("read write").asSpaceDelimited())
                .isEqualTo("read write");
    }

    @Test
    void preservesTheOrderItWasGiven() {
        assertThat(ScopeSet.fromSpaceDelimited("write read").asSpaceDelimited())
                .isEqualTo("write read");
    }

    @Test
    void treatsABlankValueAsEmpty() {
        // RFC 6749 §3.2: a parameter sent without a value is treated as if it were omitted,
        // so "" and an absent parameter must be indistinguishable from here on.
        assertThat(ScopeSet.fromSpaceDelimited("").isEmpty()).isTrue();
        assertThat(ScopeSet.fromSpaceDelimited("   ").isEmpty()).isTrue();
        assertThat(ScopeSet.fromSpaceDelimited(null).isEmpty()).isTrue();
    }

    @Test
    void collapsesDuplicateScopes() {
        assertThat(ScopeSet.fromSpaceDelimited("read read write").asSpaceDelimited())
                .isEqualTo("read write");
    }

    @Test
    void containsAllComparesByValue() {
        ScopeSet registered = ScopeSet.of("read", "write");
        assertThat(registered.containsAll(ScopeSet.of("read"))).isTrue();
        assertThat(registered.containsAll(ScopeSet.of("read", "write"))).isTrue();
        assertThat(registered.containsAll(ScopeSet.of("read", "admin"))).isFalse();
    }

    @Test
    void comparisonIsCaseSensitive() {
        assertThat(ScopeSet.of("read").containsAll(ScopeSet.of("Read"))).isFalse();
    }

    @Test
    void isImmutableAgainstTheSourceCollection() {
        java.util.Set<Scope> source = new java.util.LinkedHashSet<>();
        source.add(new Scope("read"));
        ScopeSet scopeSet = new ScopeSet(source);
        source.add(new Scope("admin"));

        assertThat(scopeSet.size()).isEqualTo(1);
    }
}
