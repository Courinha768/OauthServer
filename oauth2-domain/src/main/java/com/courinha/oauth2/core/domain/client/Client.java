package com.courinha.oauth2.core.domain.client;

import com.courinha.oauth2.core.domain.scope.ScopeSet;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * A registered client — the aggregate that answers "may this caller do this?".
 *
 * @param id               the issued {@code client_id}
 * @param secretHash       the stored secret hash, or {@code null} for a public client
 * @param type             confidential or public (§2.1)
 * @param grantTypes       the grants this client is registered for
 * @param registeredScopes the ceiling on what it may ever be granted
 * @param authMethod       how it is expected to authenticate at the token endpoint
 */
public record Client(
        ClientId id,
        SecretHash secretHash,
        ClientType type,
        Set<GrantType> grantTypes,
        ScopeSet registeredScopes,
        TokenEndpointAuthMethod authMethod) {

    public Client {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(grantTypes, "grantTypes");
        Objects.requireNonNull(registeredScopes, "registeredScopes");
        Objects.requireNonNull(authMethod, "authMethod");
        grantTypes = Collections.unmodifiableSet(new LinkedHashSet<>(grantTypes));

        if (type == ClientType.CONFIDENTIAL && secretHash == null) {
            throw new IllegalArgumentException(
                    "Confidential client '" + id.value() + "' must have a secret hash");
        }
        if (type == ClientType.PUBLIC && authMethod != TokenEndpointAuthMethod.NONE) {
            throw new IllegalArgumentException(
                    "Public client '" + id.value() + "' cannot authenticate with " + authMethod.wireValue());
        }
    }

    /** Whether this client's registration permits the given grant. */
    public boolean isGrantedFor(GrantType grantType) {
        return grantTypes.contains(grantType);
    }

    public boolean isConfidential() {
        return type == ClientType.CONFIDENTIAL;
    }

    /** Whether this client is registered to authenticate with the given method. */
    public boolean authenticatesWith(TokenEndpointAuthMethod method) {
        return authMethod == method;
    }
}
