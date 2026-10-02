package com.courinha.oauth2.core.application.port.out;

import java.time.Duration;

/**
 * Supplies the configured lifetime of an issued access token.
 */
@FunctionalInterface
public interface TokenLifetimePort {

    Duration accessTokenTtl();
}
