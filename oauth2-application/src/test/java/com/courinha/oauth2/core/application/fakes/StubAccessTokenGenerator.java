package com.courinha.oauth2.core.application.fakes;

import com.courinha.oauth2.core.application.port.out.AccessTokenGenerator;
import com.courinha.oauth2.core.application.port.out.TokenGenerationRequest;

public final class StubAccessTokenGenerator implements AccessTokenGenerator {

    private final String value;
    private int callCount;
    private TokenGenerationRequest lastRequest;
    private RuntimeException failure;

    public StubAccessTokenGenerator() {
        this("generated-token");
    }

    public StubAccessTokenGenerator(String value) {
        this.value = value;
    }

    public StubAccessTokenGenerator failingWith(RuntimeException failure) {
        this.failure = failure;
        return this;
    }

    @Override
    public String generate(TokenGenerationRequest request) {
        callCount++;
        lastRequest = request;
        if (failure != null) {
            throw failure;
        }
        return value;
    }

    public int callCount() {
        return callCount;
    }

    public TokenGenerationRequest lastRequest() {
        if (lastRequest == null) {
            throw new IllegalStateException("The generator has not been called");
        }
        return lastRequest;
    }
}
