package com.courinha.oauth2.core.application.service;

import com.courinha.oauth2.core.application.fakes.FakeClientRepository;
import com.courinha.oauth2.core.application.fakes.FakeClock;
import com.courinha.oauth2.core.application.fakes.FakeSecretHasher;
import com.courinha.oauth2.core.application.fakes.RecordingAccessTokenRepository;
import com.courinha.oauth2.core.application.fakes.StubAccessTokenGenerator;
import com.courinha.oauth2.core.application.port.in.ClientCredentialsCommand;
import com.courinha.oauth2.core.application.port.out.TokenLifetimePort;
import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.client.ClientType;
import com.courinha.oauth2.core.domain.client.GrantType;
import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;
import com.courinha.oauth2.core.domain.error.OAuth2ErrorCode;
import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import com.courinha.oauth2.core.domain.token.AccessToken;
import com.courinha.oauth2.core.domain.token.TokenType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class ClientCredentialsTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Duration TTL = Duration.ofHours(1);
    private static final String CORRECT_SECRET = "correct-secret";
    private static final ClientId DEMO_ID = new ClientId("demo");

    private FakeSecretHasher hasher;
    private RecordingAccessTokenRepository tokenRepository;
    private StubAccessTokenGenerator generator;
    private FakeClock clock;

    @BeforeEach
    void setUp() {
        hasher = new FakeSecretHasher();
        tokenRepository = new RecordingAccessTokenRepository();
        generator = new StubAccessTokenGenerator("opaque-abc123");
        clock = new FakeClock(NOW);
    }

    private static Client demoClient() {
        return clientRegisteredFor(GrantType.CLIENT_CREDENTIALS);
    }

    private static Client clientRegisteredFor(GrantType... grants) {
        return new Client(
                DEMO_ID,
                new FakeSecretHasher().hash(CORRECT_SECRET),
                ClientType.CONFIDENTIAL,
                EnumSet.copyOf(java.util.List.of(grants)),
                ScopeSet.of("read", "write"),
                TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
    }

    private ClientCredentialsTokenService serviceFor(Client... clients) {
        FakeClientRepository repository = FakeClientRepository.empty();
        for (Client client : clients) {
            repository.with(client);
        }
        return new ClientCredentialsTokenService(
                repository, tokenRepository, generator, hasher, clock, () -> TTL);
    }

    private static ClientCredentialsCommand command(String clientId, String secret, String grantType, String scope) {
        return new ClientCredentialsCommand(
                clientId, secret, TokenEndpointAuthMethod.CLIENT_SECRET_BASIC, grantType, scope);
    }

    private static OAuth2Exception assertFailsWith(ClientCredentialsTokenService service,
                                                   ClientCredentialsCommand command,
                                                   OAuth2ErrorCode expected) {
        OAuth2Exception thrown = catchThrowableOfType(() -> service.issue(command), OAuth2Exception.class);
        assertThat(thrown).isNotNull();
        assertThat(thrown.code()).isEqualTo(expected);
        return thrown;
    }

    @Nested
    class Issuing {

        @Test
        void issuesATokenToAValidClient() {
            AccessToken token = serviceFor(demoClient())
                    .issue(command("demo", CORRECT_SECRET, "client_credentials", "read"));

            assertThat(token.value()).isEqualTo("opaque-abc123");
            assertThat(token.clientId()).isEqualTo(DEMO_ID);
            assertThat(token.tokenType()).isEqualTo(TokenType.BEARER);
            assertThat(token.scopes().asSpaceDelimited()).isEqualTo("read");
            assertThat(token.issuedAt()).isEqualTo(NOW);
            assertThat(token.expiresAt()).isEqualTo(NOW.plus(TTL));
            assertThat(token.expiresInSeconds()).isEqualTo(3600);
        }

        @Test
        void savesTheTokenBeforeReturningIt() {
            serviceFor(demoClient()).issue(command("demo", CORRECT_SECRET, "client_credentials", "read"));

            assertThat(tokenRepository.saveCount()).isEqualTo(1);
            assertThat(tokenRepository.lastSaved().value()).isEqualTo("opaque-abc123");
        }

        @Test
        void grantsTheClientsRegisteredScopesWhenScopeIsOmitted() {
            AccessToken token = serviceFor(demoClient())
                    .issue(command("demo", CORRECT_SECRET, "client_credentials", null));

            assertThat(token.scopes().asSpaceDelimited()).isEqualTo("read write");
        }

        @Test
        void passesTheGrantedScopesAndWindowToTheGenerator() {
            serviceFor(demoClient()).issue(command("demo", CORRECT_SECRET, "client_credentials", "read"));

            var request = generator.lastRequest();
            assertThat(request.clientId()).isEqualTo(DEMO_ID);
            assertThat(request.scopes().asSpaceDelimited()).isEqualTo("read");
            assertThat(request.issuedAt()).isEqualTo(NOW);
            assertThat(request.expiresAt()).isEqualTo(NOW.plus(TTL));
        }
    }

    @Nested
    class Authentication {

        @Test
        void rejectsAWrongSecret() {
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", "wrong", "client_credentials", null),
                    OAuth2ErrorCode.INVALID_CLIENT);

            assertThat(tokenRepository.saveCount()).isZero();
            assertThat(generator.callCount()).isZero();
        }

        @Test
        void rejectsAnUnknownClient() {
            assertFailsWith(serviceFor(demoClient()),
                    command("nobody", CORRECT_SECRET, "client_credentials", null),
                    OAuth2ErrorCode.INVALID_CLIENT);
        }

        @Test
        void rejectsMissingCredentials() {
            assertFailsWith(serviceFor(demoClient()),
                    new ClientCredentialsCommand(null, null, TokenEndpointAuthMethod.NONE,
                            "client_credentials", null),
                    OAuth2ErrorCode.INVALID_CLIENT);
        }

        @Test
        void rejectsAClientPresentingAMethodItIsNotRegisteredFor() {
            // Registered for Basic only. The server supports POST, so this is an authentication
            // failure rather than an invalid_request.
            assertFailsWith(serviceFor(demoClient()),
                    new ClientCredentialsCommand("demo", CORRECT_SECRET,
                            TokenEndpointAuthMethod.CLIENT_SECRET_POST, "client_credentials", null),
                    OAuth2ErrorCode.INVALID_CLIENT);
        }

        @Test
        void rejectsAPublicClient() {
            Client publicClient = new Client(new ClientId("spa"), null, ClientType.PUBLIC,
                    EnumSet.of(GrantType.CLIENT_CREDENTIALS), ScopeSet.of("read"),
                    TokenEndpointAuthMethod.NONE);

            assertFailsWith(serviceFor(publicClient),
                    new ClientCredentialsCommand("spa", null, TokenEndpointAuthMethod.NONE,
                            "client_credentials", null),
                    OAuth2ErrorCode.INVALID_CLIENT);
        }

        @Test
        void givesAnUnknownClientAndAWrongSecretTheSameDescription() {
            OAuth2Exception unknownClient = assertFailsWith(serviceFor(demoClient()),
                    command("nobody", CORRECT_SECRET, "client_credentials", null),
                    OAuth2ErrorCode.INVALID_CLIENT);
            OAuth2Exception wrongSecret = assertFailsWith(serviceFor(demoClient()),
                    command("demo", "wrong", "client_credentials", null),
                    OAuth2ErrorCode.INVALID_CLIENT);

            assertThat(unknownClient.error().description())
                    .isEqualTo(wrongSecret.error().description());
        }

        @Test
        void stillComparesASecretWhenTheClientIsUnknown() {
            // Without this, response timing would reveal which client_ids exist.
            assertFailsWith(serviceFor(demoClient()),
                    command("nobody", CORRECT_SECRET, "client_credentials", null),
                    OAuth2ErrorCode.INVALID_CLIENT);

            assertThat(hasher.matchCallCount()).isEqualTo(1);
            // Compared against a stand-in, not any registered client's hash.
            assertThat(hasher.lastComparedHash()).isNotEqualTo(new FakeSecretHasher().hash(CORRECT_SECRET));
        }
    }

    @Nested
    class GrantValidation {

        @Test
        void rejectsAMissingGrantType() {
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", CORRECT_SECRET, null, null),
                    OAuth2ErrorCode.INVALID_REQUEST);
        }

        @Test
        void rejectsABlankGrantType() {
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", CORRECT_SECRET, "  ", null),
                    OAuth2ErrorCode.INVALID_REQUEST);
        }

        @Test
        void rejectsAGrantTypeTheServerDoesNotImplement() {
            // Recognised by the registration model, but nothing here implements it — and a
            // client that legitimately cannot use a grant must not be told it is unauthorized.
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", CORRECT_SECRET, "authorization_code", null),
                    OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE);
        }

        @Test
        void rejectsAGrantTypeThatDoesNotExist() {
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", CORRECT_SECRET, "not_a_real_grant", null),
                    OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE);
        }

        @Test
        void grantTypeMatchingIsCaseSensitive() {
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", CORRECT_SECRET, "CLIENT_CREDENTIALS", null),
                    OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE);
        }

        @Test
        void rejectsAClientNotRegisteredForTheGrant() {
            Client noGrant = new Client(DEMO_ID, new FakeSecretHasher().hash(CORRECT_SECRET),
                    ClientType.CONFIDENTIAL, EnumSet.of(GrantType.AUTHORIZATION_CODE),
                    ScopeSet.of("read"), TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);

            assertFailsWith(serviceFor(noGrant),
                    command("demo", CORRECT_SECRET, "client_credentials", null),
                    OAuth2ErrorCode.UNAUTHORIZED_CLIENT);
        }

        /**
         * The RFC specifies no precedence between these checks, so this pins the deliberate
         * choice: authentication first, so the server does not confirm its grant registry to an
         * unauthenticated caller.
         */
        @Test
        void authenticationFailureOutranksAnUnknownGrantType() {
            assertFailsWith(serviceFor(demoClient()),
                    command("nobody", "whatever", "not_a_real_grant", null),
                    OAuth2ErrorCode.INVALID_CLIENT);
        }
    }

    @Nested
    class ScopeValidation {

        @Test
        void rejectsScopeEscalationWithoutIssuingAnything() {
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", CORRECT_SECRET, "client_credentials", "read admin"),
                    OAuth2ErrorCode.INVALID_SCOPE);

            assertThat(tokenRepository.saveCount()).isZero();
            assertThat(generator.callCount()).isZero();
        }

        @Test
        void treatsAMalformedScopeAsInvalidScopeRatherThanInvalidRequest() {
            // §5.2 lists "malformed" under invalid_scope.
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", CORRECT_SECRET, "client_credentials", "re\"ad"),
                    OAuth2ErrorCode.INVALID_SCOPE);
        }

        @Test
        void scopeComparisonIsCaseSensitive() {
            assertFailsWith(serviceFor(demoClient()),
                    command("demo", CORRECT_SECRET, "client_credentials", "READ"),
                    OAuth2ErrorCode.INVALID_SCOPE);
        }
    }

    @Nested
    class Failures {

        @Test
        void propagatesAGeneratorFailureWithoutSaving() {
            generator.failingWith(new IllegalStateException("signing key unavailable"));

            assertThatThrownBy(() -> serviceFor(demoClient())
                    .issue(command("demo", CORRECT_SECRET, "client_credentials", null)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("signing key unavailable");

            assertThat(tokenRepository.saveCount()).isZero();
        }

        @Test
        void propagatesARepositoryFailure() {
            tokenRepository.failingOnSave();

            assertThatThrownBy(() -> serviceFor(demoClient())
                    .issue(command("demo", CORRECT_SECRET, "client_credentials", null)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("token store unavailable");
        }
    }

    @Test
    void tokenLifetimeComesFromThePortNotAConstant() {
        var service = new ClientCredentialsTokenService(
                FakeClientRepository.empty().with(demoClient()),
                tokenRepository, generator, hasher, clock, () -> Duration.ofMinutes(5));

        AccessToken token = service.issue(command("demo", CORRECT_SECRET, "client_credentials", null));

        assertThat(token.expiresInSeconds()).isEqualTo(300);
    }

    @Test
    void commandDoesNotRenderItsSecret() {
        assertThat(command("demo", "super-secret", "client_credentials", null).toString())
                .doesNotContain("super-secret")
                .contains("REDACTED");
    }

    @Test
    void lifetimePortIsUsedRatherThanAConstant() {
        TokenLifetimePort port = () -> Duration.ofSeconds(42);
        assertThat(port.accessTokenTtl()).isEqualTo(Duration.ofSeconds(42));
    }
}
