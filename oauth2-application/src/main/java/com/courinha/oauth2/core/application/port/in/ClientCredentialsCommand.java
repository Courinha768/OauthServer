package com.courinha.oauth2.core.application.port.in;

import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A token request as the web adapter understood it, before any protocol semantics are applied.
 *
 * <p>The fields are deliberately raw. Deciding what a shape problem <em>means</em> — a malformed
 * scope, an unrecognised grant, an authentication failure — belongs to the use case, not to the
 * parser, so that every rule is testable without HTTP.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientCredentialsCommand {

    /** The presented client identifier, or {@code null} if absent. */
    private String clientId;

    /** The presented secret, or {@code null} if absent. */
    private String clientSecret;

    /** How the credentials arrived; {@code NONE} when none were presented. */
    private TokenEndpointAuthMethod presentedMethod;

    /** The raw {@code grant_type} parameter, or {@code null} if absent. */
    private String grantType;

    /** The raw {@code scope} parameter, or {@code null} if absent. */
    private String scope;

    /**
     * Redacts the secret. Generated accessors would otherwise render every field, and this
     * object travels through logging and exception paths.
     */
    @Override
    public String toString() {
        return "ClientCredentialsCommand[clientId=%s, clientSecret=REDACTED, presentedMethod=%s, grantType=%s, scope=%s]"
                .formatted(clientId, presentedMethod, grantType, scope);
    }
}
