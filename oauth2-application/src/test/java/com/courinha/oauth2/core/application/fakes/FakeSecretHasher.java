package com.courinha.oauth2.core.application.fakes;

import com.courinha.oauth2.core.application.port.out.ClientSecretHasher;
import com.courinha.oauth2.core.domain.client.SecretHash;

import java.util.ArrayList;
import java.util.List;

/**
 * A hasher that is trivially reversible, so tests can state secrets in the clear, while
 * recording every verification attempt.
 *
 * <p>The recording is what makes the timing-oracle defence testable: a test can assert that a
 * comparison happened even when the client was not found.
 */
public final class FakeSecretHasher implements ClientSecretHasher {

    public static final String HASH_PREFIX = "hashed:";

    private final List<SecretHash> matchCalls = new ArrayList<>();

    @Override
    public SecretHash hash(String rawSecret) {
        return new SecretHash(HASH_PREFIX + rawSecret);
    }

    @Override
    public boolean matches(String rawSecret, SecretHash storedHash) {
        matchCalls.add(storedHash);
        return storedHash != null && storedHash.value().equals(HASH_PREFIX + rawSecret);
    }

    /** How many comparisons have been attempted. */
    public int matchCallCount() {
        return matchCalls.size();
    }

    /** The hash the most recent comparison was made against. */
    public SecretHash lastComparedHash() {
        if (matchCalls.isEmpty()) {
            throw new IllegalStateException("No comparison has been attempted");
        }
        return matchCalls.get(matchCalls.size() - 1);
    }
}
