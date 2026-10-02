package com.courinha.oauth2.core.adapter.out.time.system;

import com.courinha.oauth2.core.application.port.out.ClockPort;

import java.time.Instant;

/**
 * The production {@link ClockPort}. This is the only place in the codebase permitted to read
 * the wall clock; everything else takes the time as a parameter, which is what keeps expiry
 * assertions deterministic.
 */
public final class SystemClockAdapter implements ClockPort {

    @Override
    public Instant now() {
        return Instant.now();
    }
}
