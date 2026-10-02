package com.courinha.oauth2.core.domain.policy;

import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import com.courinha.oauth2.core.domain.scope.ScopeSet;

/**
 * Decides which scopes a client may actually be granted.
 *
 * <p>RFC 6749 §3.3 leaves the server a choice when the client omits {@code scope}: use a
 * pre-defined default, or fail with {@code invalid_scope}. Those are the only two conforming
 * behaviours. This server uses the client's registered scopes as the documented default, so an
 * omitting client receives exactly the ceiling it was registered for and never more.
 */
public final class ScopePolicy {

    private ScopePolicy() {
    }

    /**
     * Resolves the scopes to grant.
     *
     * @param client    the authenticated client
     * @param requested the scopes asked for; empty means the parameter was absent or valueless
     * @return the scopes to grant
     * @throws OAuth2Exception {@code invalid_scope} if the request exceeds the client's registration
     */
    public static ScopeSet resolve(Client client, ScopeSet requested) {
        if (requested.isEmpty()) {
            return client.registeredScopes();
        }
        if (!client.registeredScopes().containsAll(requested)) {
            throw OAuth2Exception.invalidScope();
        }
        return requested;
    }
}
