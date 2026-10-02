package com.courinha.oauth2.core.domain.policy;

import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.client.ClientType;
import com.courinha.oauth2.core.domain.client.GrantType;
import com.courinha.oauth2.core.domain.client.SecretHash;
import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;
import com.courinha.oauth2.core.domain.error.OAuth2ErrorCode;
import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScopePolicyTest {

    private static final Client CLIENT = new Client(
            new ClientId("demo"),
            new SecretHash("$2a$10$hash"),
            ClientType.CONFIDENTIAL,
            EnumSet.of(GrantType.CLIENT_CREDENTIALS),
            ScopeSet.of("read", "write"),
            TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);

    @Test
    void omittingScopeGrantsTheClientsRegisteredScopes() {
        // RFC 6749 §3.3 permits a documented pre-defined default; ours is the registration itself.
        assertThat(ScopePolicy.resolve(CLIENT, ScopeSet.empty()).asSpaceDelimited())
                .isEqualTo("read write");
    }

    @Test
    void grantsASubsetOfTheRegisteredScopes() {
        assertThat(ScopePolicy.resolve(CLIENT, ScopeSet.of("read")).asSpaceDelimited())
                .isEqualTo("read");
    }

    @Test
    void refusesToEscalateBeyondTheRegisteredScopes() {
        assertThatThrownBy(() -> ScopePolicy.resolve(CLIENT, ScopeSet.of("read", "admin")))
                .isInstanceOf(OAuth2Exception.class)
                .extracting(e -> ((OAuth2Exception) e).code())
                .isEqualTo(OAuth2ErrorCode.INVALID_SCOPE);
    }

    @Test
    void escalationIsCaseSensitive() {
        assertThatThrownBy(() -> ScopePolicy.resolve(CLIENT, ScopeSet.of("READ")))
                .isInstanceOf(OAuth2Exception.class);
    }
}
