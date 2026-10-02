package com.courinha.oauth2.core.config;

import com.courinha.oauth2.core.adapter.out.persistence.inmemory.InMemoryClientRepository;
import com.courinha.oauth2.core.application.port.out.ClientSecretHasher;
import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.client.ClientType;
import com.courinha.oauth2.core.domain.client.GrantType;
import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.EnumSet;

/**
 * Seeds demo clients so the endpoint is exercisable immediately after startup.
 *
 * <p>Iteration 1 has no client registration endpoint, and the in-memory repositories start
 * empty. These are development fixtures: a real deployment would register clients properly and
 * would not ship a known secret.
 */
@Configuration(proxyBeanMethods = false)
public class ClientSeedConfiguration {

    private static final Logger log = LoggerFactory.getLogger(ClientSeedConfiguration.class);

    /** Contains a space, '+', '%', '&', ':' and a non-ASCII character, for Appendix B testing. */
    private static final String SPECIAL_SECRET = "p@ss w+rd%&:é";

    @Bean
    public ApplicationRunner seedDemoClients(InMemoryClientRepository clients, ClientSecretHasher hasher) {
        return args -> {
            clients.add(Client.builder()
                    .id(new ClientId("demo-basic"))
                    .secretHash(hasher.hash("secret"))
                    .type(ClientType.CONFIDENTIAL)
                    .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                    .registeredScopes(ScopeSet.of("read", "write"))
                    .authMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                    .build());

            clients.add(Client.builder()
                    .id(new ClientId("demo-post"))
                    .secretHash(hasher.hash("secret"))
                    .type(ClientType.CONFIDENTIAL)
                    .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                    .registeredScopes(ScopeSet.of("read"))
                    .authMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                    .build());

            clients.add(Client.builder()
                    .id(new ClientId("demo-special"))
                    .secretHash(hasher.hash(SPECIAL_SECRET))
                    .type(ClientType.CONFIDENTIAL)
                    .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                    .registeredScopes(ScopeSet.of("read"))
                    .authMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                    .build());

            log.info("Seeded {} demo clients", clients.size());
        };
    }
}
