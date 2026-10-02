package com.courinha.oauth2.core.adapter.out.secret.bcrypt;

import com.courinha.oauth2.core.application.port.out.ClientSecretHasher;
import com.courinha.oauth2.core.domain.client.SecretHash;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * BCrypt-backed secret hashing, via the standalone {@code spring-security-crypto} artifact.
 *
 * <p>BCrypt is deliberately slow and salts each hash, so a stolen client table does not yield
 * reusable secrets. Comparison is constant-time within the algorithm.
 */
public final class BCryptClientSecretHasher implements ClientSecretHasher {

    private final BCryptPasswordEncoder encoder;

    public BCryptClientSecretHasher() {
        this(new BCryptPasswordEncoder());
    }

    public BCryptClientSecretHasher(BCryptPasswordEncoder encoder) {
        this.encoder = encoder;
    }

    @Override
    public SecretHash hash(String rawSecret) {
        return new SecretHash(encoder.encode(rawSecret));
    }

    @Override
    public boolean matches(String rawSecret, SecretHash storedHash) {
        if (rawSecret == null || storedHash == null) {
            return false;
        }
        return encoder.matches(rawSecret, storedHash.value());
    }
}
