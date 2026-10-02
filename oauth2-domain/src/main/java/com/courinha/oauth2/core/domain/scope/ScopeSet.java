package com.courinha.oauth2.core.domain.scope;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A set of {@link Scope}s, insertion-ordered.
 *
 * <p>Order is preserved because the set is rendered back to the client as a space-delimited
 * string, and echoing the requested order keeps responses stable and diffable.
 */
@Data
@NoArgsConstructor
public class ScopeSet {

    private Set<Scope> scopes = new LinkedHashSet<>();

    /** Copies defensively, so the caller's collection cannot mutate this set behind its back. */
    @Builder
    public ScopeSet(Set<Scope> scopes) {
        Objects.requireNonNull(scopes, "scopes");
        this.scopes = new LinkedHashSet<>(scopes);
    }

    public static ScopeSet empty() {
        return new ScopeSet(Set.of());
    }

    public static ScopeSet of(Scope... scopes) {
        return new ScopeSet(new LinkedHashSet<>(Arrays.asList(scopes)));
    }

    public static ScopeSet of(String... values) {
        return new ScopeSet(Arrays.stream(values)
                .map(Scope::new)
                .collect(Collectors.toCollection(LinkedHashSet::new)));
    }

    /**
     * Parses the {@code scope} request parameter, whose value is a list of space-delimited
     * tokens (§3.3).
     *
     * <p>A blank value yields the empty set. That is intentional rather than a special case:
     * §3.2 requires a parameter sent without a value to be treated as if it were omitted, so an
     * empty set and an absent parameter are meant to be indistinguishable from here on.
     */
    public static ScopeSet fromSpaceDelimited(String value) {
        if (value == null || value.isBlank()) {
            return empty();
        }
        return new ScopeSet(Arrays.stream(value.split(" "))
                .filter(token -> !token.isEmpty())
                .map(Scope::new)
                .collect(Collectors.toCollection(LinkedHashSet::new)));
    }

    public boolean isEmpty() {
        return scopes.isEmpty();
    }

    public int size() {
        return scopes.size();
    }

    /** True when every scope in {@code other} is present here. */
    public boolean containsAll(ScopeSet other) {
        return scopes.containsAll(other.getScopes());
    }

    /** Renders the set in the wire format the {@code scope} response member uses. */
    public String asSpaceDelimited() {
        return scopes.stream().map(Scope::getValue).collect(Collectors.joining(" "));
    }

    @Override
    public String toString() {
        return asSpaceDelimited();
    }
}
