package com.courinha.oauth2.core.application.port.out;

import java.time.Instant;

/**
 * Supplies the current time.
 *
 * <p>A port rather than a direct {@code Instant.now()} call so that token expiry is decided by a
 * collaborator tests can control. Without it, every assertion about {@code exp} would depend on
 * wall-clock timing and eventually turn flaky.
 */
@FunctionalInterface
public interface ClockPort {

    Instant now();
}
