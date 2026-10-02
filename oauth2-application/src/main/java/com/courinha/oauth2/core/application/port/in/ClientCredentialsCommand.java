package com.courinha.oauth2.core.application.port.in;

import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;

/**
 * A token request as the web adapter understood it, before any protocol semantics are applied.
 *
 * <p>The fields are deliberately raw. Deciding what a shape problem <em>means</em> — a malformed
 * scope, an unrecognised grant, an authentication failure — belongs to the use case, not to the
 * parser, so that every rule is testable without HTTP.
 *
 * @param clientId        the presented client identifier, or {@code null} if absent
 * @param clientSecret    the presented secret, or {@code null} if absent
 * @param presentedMethod how the credentials arrived; {@link TokenEndpointAuthMethod#NONE} when
 *                        none were presented
 * @param grantType       the raw {@code grant_type} parameter, or {@code null} if absent
 * @param scope           the raw {@code scope} parameter, or {@code null} if absent
 */
public record ClientCredentialsCommand(
        String clientId,
        String clientSecret,
        TokenEndpointAuthMethod presentedMethod,
        String grantType,
        String scope) {

    /**
     * Redacts the secret. A record's generated {@code toString()} would print every component,
     * and this object travels through logging and exception paths.
     */
    @Override
    public String toString() {
        return "ClientCredentialsCommand[clientId=%s, clientSecret=REDACTED, presentedMethod=%s, grantType=%s, scope=%s]"
                .formatted(clientId, presentedMethod, grantType, scope);
    }
}
