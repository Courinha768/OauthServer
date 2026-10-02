package com.courinha.oauth2.core.application.port.out;

import com.courinha.oauth2.core.domain.client.SecretHash;

/**
 * Hashes and verifies client secrets.
 *
 * <p>Split into two methods rather than one because registering a client and authenticating one
 * are different concerns that happen to share an algorithm.
 */
public interface ClientSecretHasher {

    /** Hashes a plaintext secret for storage. Called at registration, never at authentication. */
    SecretHash hash(String rawSecret);

    /**
     * Verifies a presented secret against a stored hash. Implementations must compare in a way
     * that does not leak the correct value through timing.
     */
    boolean matches(String rawSecret, SecretHash storedHash);
}
