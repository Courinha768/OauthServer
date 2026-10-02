package com.courinha.oauth2.core.adapter.out.policy.fixed;

import com.courinha.oauth2.core.application.port.out.TokenLifetimePort;

import java.time.Duration;
import java.util.Objects;

/**
 * A {@link TokenLifetimePort} configured once at startup.
 */
public final class FixedTokenLifetimeAdapter implements TokenLifetimePort {

    private final Duration accessTokenTtl;

    public FixedTokenLifetimeAdapter(Duration accessTokenTtl) {
        this.accessTokenTtl = Objects.requireNonNull(accessTokenTtl, "accessTokenTtl");
        if (accessTokenTtl.isZero() || accessTokenTtl.isNegative()) {
            throw new IllegalArgumentException("accessTokenTtl must be positive, was " + accessTokenTtl);
        }
    }

    @Override
    public Duration accessTokenTtl() {
        return accessTokenTtl;
    }
}
