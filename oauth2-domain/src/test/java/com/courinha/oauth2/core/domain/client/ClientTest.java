package com.courinha.oauth2.core.domain.client;

import com.courinha.oauth2.core.domain.scope.ScopeSet;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientTest {

    private static Client confidential() {
        return new Client(
                new ClientId("demo"),
                new SecretHash("$2a$10$hash"),
                ClientType.CONFIDENTIAL,
                EnumSet.of(GrantType.CLIENT_CREDENTIALS),
                ScopeSet.of("read"),
                TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    void reportsTheGrantsItIsRegisteredFor() {
        Client client = confidential();

        assertThat(client.isGrantedFor(GrantType.CLIENT_CREDENTIALS)).isTrue();
        assertThat(client.isGrantedFor(GrantType.AUTHORIZATION_CODE)).isFalse();
        assertThat(client.isConfidential()).isTrue();
    }

    @Test
    void reportsTheAuthMethodItIsRegisteredFor() {
        Client client = confidential();

        assertThat(client.authenticatesWith(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)).isTrue();
        assertThat(client.authenticatesWith(TokenEndpointAuthMethod.CLIENT_SECRET_POST)).isFalse();
    }

    @Test
    void rejectsAConfidentialClientWithoutASecret() {
        assertThatThrownBy(() -> new Client(new ClientId("demo"), null, ClientType.CONFIDENTIAL,
                EnumSet.of(GrantType.CLIENT_CREDENTIALS), ScopeSet.of("read"),
                TokenEndpointAuthMethod.CLIENT_SECRET_BASIC))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must have a secret hash");
    }

    @Test
    void rejectsAPublicClientThatClaimsASecretAuthMethod() {
        assertThatThrownBy(() -> new Client(new ClientId("spa"), new SecretHash("$2a$10$hash"),
                ClientType.PUBLIC, EnumSet.of(GrantType.AUTHORIZATION_CODE), ScopeSet.of("read"),
                TokenEndpointAuthMethod.CLIENT_SECRET_BASIC))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot authenticate with");
    }

    @Test
    void allowsAPublicClientWithNoAuthentication() {
        Client client = new Client(new ClientId("spa"), null, ClientType.PUBLIC,
                EnumSet.of(GrantType.AUTHORIZATION_CODE), ScopeSet.of("read"),
                TokenEndpointAuthMethod.NONE);

        assertThat(client.isConfidential()).isFalse();
        assertThat(client.secretHash()).isNull();
    }

    @Test
    void grantTypesAreImmutableAgainstTheSourceCollection() {
        var source = EnumSet.of(GrantType.CLIENT_CREDENTIALS);
        Client client = new Client(new ClientId("demo"), new SecretHash("$2a$10$hash"),
                ClientType.CONFIDENTIAL, source, ScopeSet.of("read"),
                TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        source.add(GrantType.PASSWORD);

        assertThat(client.grantTypes()).containsExactly(GrantType.CLIENT_CREDENTIALS);
    }

    @Test
    void grantTypeWireValuesRoundTripCaseSensitively() {
        assertThat(GrantType.fromWire("client_credentials")).contains(GrantType.CLIENT_CREDENTIALS);
        // RFC 6749 §4.4.2: the value must match exactly.
        assertThat(GrantType.fromWire("CLIENT_CREDENTIALS")).isEmpty();
        assertThat(GrantType.fromWire("client_credential")).isEmpty();
        assertThat(GrantType.fromWire(null)).isEmpty();
    }

    @Test
    void authMethodWireValuesRoundTrip() {
        assertThat(TokenEndpointAuthMethod.fromWire("client_secret_basic"))
                .contains(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        assertThat(TokenEndpointAuthMethod.fromWire("client_secret_post"))
                .contains(TokenEndpointAuthMethod.CLIENT_SECRET_POST);
        assertThat(TokenEndpointAuthMethod.fromWire("nope")).isEqualTo(Optional.empty());
    }

    @Test
    void aSecretHashNeverRendersItself() {
        assertThat(new SecretHash("$2a$10$supersecrethash").toString())
                .isEqualTo("SecretHash[REDACTED]")
                .doesNotContain("supersecrethash");
    }

    @Test
    void rejectsABlankSecretHash() {
        assertThatThrownBy(() -> new SecretHash("  "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsABlankClientId() {
        assertThatThrownBy(() -> new ClientId(""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
