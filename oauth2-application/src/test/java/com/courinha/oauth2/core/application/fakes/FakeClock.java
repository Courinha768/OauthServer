package com.courinha.oauth2.core.application.fakes;

import com.courinha.oauth2.core.application.port.out.ClockPort;

import java.time.Instant;

/** A clock that only moves when a test moves it, so expiry assertions cannot go flaky. */
public final class FakeClock implements ClockPort {

    private Instant now;

    public FakeClock(Instant now) {
        this.now = now;
    }

    @Override
    public Instant now() {
        return now;
    }

    public void advanceTo(Instant instant) {
        this.now = instant;
    }
}
