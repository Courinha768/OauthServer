package com.courinha.oauth2.core.adapter.in.web;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Credentials recovered from an {@code Authorization: Basic} header.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BasicCredentials {

    private String clientId;

    /** May be empty, which §2.3.1 permits. */
    private String clientSecret;

    /** Redacts the secret: this object is built from a header and must not be logged whole. */
    @Override
    public String toString() {
        return "BasicCredentials[clientId=%s, clientSecret=REDACTED]".formatted(clientId);
    }
}
