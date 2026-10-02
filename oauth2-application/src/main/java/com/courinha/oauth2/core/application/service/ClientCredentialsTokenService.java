package com.courinha.oauth2.core.application.service;

import com.courinha.oauth2.core.application.port.in.ClientCredentialsCommand;
import com.courinha.oauth2.core.application.port.in.IssueClientCredentialsTokenUseCase;
import com.courinha.oauth2.core.application.port.out.AccessTokenGenerator;
import com.courinha.oauth2.core.application.port.out.AccessTokenRepository;
import com.courinha.oauth2.core.application.port.out.ClientRepository;
import com.courinha.oauth2.core.application.port.out.ClientSecretHasher;
import com.courinha.oauth2.core.application.port.out.ClockPort;
import com.courinha.oauth2.core.application.port.out.TokenGenerationRequest;
import com.courinha.oauth2.core.application.port.out.TokenLifetimePort;
import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.client.GrantType;
import com.courinha.oauth2.core.domain.client.SecretHash;
import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import com.courinha.oauth2.core.domain.policy.ScopePolicy;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import com.courinha.oauth2.core.domain.token.AccessToken;
import com.courinha.oauth2.core.domain.token.TokenType;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * RFC 6749 §4.4, the client credentials grant.
 *
 * <p>The order of the checks below is a deliberate choice, because the RFC does not specify one.
 * Client authentication runs <em>before</em> the grant type is recognised: §3.2.1 makes
 * authentication a precondition for the rest of the request, §5.2 defines
 * {@code unauthorized_client} in terms of the <em>authenticated</em> client, and answering
 * {@code unsupported_grant_type} to an unauthenticated caller would confirm the server's grant
 * registry to anyone who asks.
 */
public final class ClientCredentialsTokenService implements IssueClientCredentialsTokenUseCase {

    /**
     * A syntactically valid BCrypt hash, compared against when the client is unknown.
     *
     * <p>Its value is irrelevant — nothing is protected by it. It exists so that authentication
     * performs the same work whether or not the {@code client_id} exists, which is what stops
     * response timing from becoming a client-enumeration oracle.
     */
    private static final SecretHash TIMING_EQUALISATION_HASH =
            new SecretHash("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");

    /**
     * The grants this server actually implements.
     *
     * <p>Distinct from {@link GrantType}, which models every grant a client registration may
     * name. A request for a recognised-but-unimplemented grant is {@code unsupported_grant_type}
     * ("not supported by the authorization server", §5.2) — not {@code unauthorized_client},
     * which is about what the authenticated client is permitted to do. Grows as grants land.
     */
    private static final Set<GrantType> SUPPORTED_GRANTS = EnumSet.of(GrantType.CLIENT_CREDENTIALS);

    private final ClientRepository clientRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final AccessTokenGenerator accessTokenGenerator;
    private final ClientSecretHasher clientSecretHasher;
    private final ClockPort clock;
    private final TokenLifetimePort tokenLifetime;

    public ClientCredentialsTokenService(
            ClientRepository clientRepository,
            AccessTokenRepository accessTokenRepository,
            AccessTokenGenerator accessTokenGenerator,
            ClientSecretHasher clientSecretHasher,
            ClockPort clock,
            TokenLifetimePort tokenLifetime) {
        this.clientRepository = Objects.requireNonNull(clientRepository, "clientRepository");
        this.accessTokenRepository = Objects.requireNonNull(accessTokenRepository, "accessTokenRepository");
        this.accessTokenGenerator = Objects.requireNonNull(accessTokenGenerator, "accessTokenGenerator");
        this.clientSecretHasher = Objects.requireNonNull(clientSecretHasher, "clientSecretHasher");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.tokenLifetime = Objects.requireNonNull(tokenLifetime, "tokenLifetime");
    }

    @Override
    public AccessToken issue(ClientCredentialsCommand command) {
        requireGrantTypePresent(command);

        Client client = authenticate(command);

        GrantType grantType = GrantType.fromWire(command.grantType())
                .filter(SUPPORTED_GRANTS::contains)
                .orElseThrow(OAuth2Exception::unsupportedGrantType);

        if (!client.isGrantedFor(grantType)) {
            throw OAuth2Exception.unauthorizedClient();
        }

        ScopeSet granted = ScopePolicy.resolve(client, requestedScopes(command.scope()));

        Instant issuedAt = clock.now();
        Instant expiresAt = issuedAt.plus(tokenLifetime.accessTokenTtl());

        String value = accessTokenGenerator.generate(
                new TokenGenerationRequest(client.id(), granted, issuedAt, expiresAt));

        AccessToken token =
                new AccessToken(value, client.id(), granted, TokenType.BEARER, issuedAt, expiresAt);

        // Saved before returning, so an opaque token is resolvable the moment the client has it.
        accessTokenRepository.save(token);
        return token;
    }

    private static void requireGrantTypePresent(ClientCredentialsCommand command) {
        if (command.grantType() == null || command.grantType().isBlank()) {
            throw OAuth2Exception.invalidRequest("Missing required parameter: grant_type");
        }
    }

    /**
     * Verifies the client's credentials.
     *
     * <p>Every failure — unknown client, absent credentials, wrong secret, a method the client
     * is not registered for, or a client that is not confidential — produces the same
     * {@code invalid_client} error with the same description, and does the same amount of work.
     */
    private Client authenticate(ClientCredentialsCommand command) {
        String rawClientId = command.clientId();
        String rawSecret = command.clientSecret() == null ? "" : command.clientSecret();

        Client client = (rawClientId == null || rawClientId.isBlank())
                ? null
                : clientRepository.findByClientId(new ClientId(rawClientId)).orElse(null);

        SecretHash hashToCheck = (client != null && client.secretHash() != null)
                ? client.secretHash()
                : TIMING_EQUALISATION_HASH;
        boolean secretMatches = clientSecretHasher.matches(rawSecret, hashToCheck);

        if (client == null
                || !secretMatches
                || !client.isConfidential()
                || !client.authenticatesWith(command.presentedMethod())) {
            throw OAuth2Exception.invalidClient();
        }
        return client;
    }

    private static ScopeSet requestedScopes(String rawScope) {
        try {
            return ScopeSet.fromSpaceDelimited(rawScope);
        } catch (IllegalArgumentException e) {
            // §5.2 lists "malformed" under invalid_scope, so a bad scope token is not an
            // invalid_request even though it is a parameter problem.
            throw OAuth2Exception.invalidScope();
        }
    }
}
