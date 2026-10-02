package com.courinha.oauth2.core.adapter.out.persistence.inmemory;

import com.courinha.oauth2.core.application.port.out.AccessTokenRepository;
import com.courinha.oauth2.core.domain.token.AccessToken;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A map-backed {@link AccessTokenRepository}, keyed by token value.
 *
 * <p>This is what makes an opaque token resolvable, and what will make revocation a delete for
 * both token formats.
 */
public final class InMemoryAccessTokenRepository implements AccessTokenRepository {

    private final ConcurrentMap<String, AccessToken> tokens = new ConcurrentHashMap<>();

    @Override
    public void save(AccessToken token) {
        tokens.put(token.getValue(), token);
    }

    public Optional<AccessToken> findByValue(String value) {
        return Optional.ofNullable(tokens.get(value));
    }

    public int size() {
        return tokens.size();
    }
}
