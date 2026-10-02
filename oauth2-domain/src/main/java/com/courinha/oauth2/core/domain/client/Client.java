package com.courinha.oauth2.core.domain.client;

import com.courinha.oauth2.core.domain.scope.ScopeSet;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * A registered client — the aggregate that answers "may this caller do this?".
 */
@Data
@NoArgsConstructor
public class Client {

    private ClientId id;

    /** Excluded from {@code toString()} so a log line cannot leak a stored secret hash. */
    @ToString.Exclude
    private SecretHash secretHash;

    private ClientType type;

    private Set<GrantType> grantTypes = new LinkedHashSet<>();

    /** The ceiling on what this client may ever be granted. */
    private ScopeSet registeredScopes;

    private TokenEndpointAuthMethod authMethod;

    @Builder
    public Client(ClientId id,
                  SecretHash secretHash,
                  ClientType type,
                  Set<GrantType> grantTypes,
                  ScopeSet registeredScopes,
                  TokenEndpointAuthMethod authMethod) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(grantTypes, "grantTypes");
        Objects.requireNonNull(registeredScopes, "registeredScopes");
        Objects.requireNonNull(authMethod, "authMethod");

        if (type == ClientType.CONFIDENTIAL && secretHash == null) {
            throw new IllegalArgumentException(
                    "Confidential client '" + id.getValue() + "' must have a secret hash");
        }
        if (type == ClientType.PUBLIC && authMethod != TokenEndpointAuthMethod.NONE) {
            throw new IllegalArgumentException(
                    "Public client '" + id.getValue() + "' cannot authenticate with " + authMethod.getWireValue());
        }

        this.id = id;
        this.secretHash = secretHash;
        this.type = type;
        this.grantTypes = new LinkedHashSet<>(grantTypes);
        this.registeredScopes = registeredScopes;
        this.authMethod = authMethod;
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
