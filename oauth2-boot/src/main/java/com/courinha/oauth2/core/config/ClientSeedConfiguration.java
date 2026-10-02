package com.courinha.oauth2.core.config;

import com.courinha.oauth2.core.adapter.out.persistence.file.FileClientRepository;
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.EnumSet;
import java.util.function.Consumer;

/**
 * Seeds demo clients so the endpoint is exercisable immediately after startup.
 *
 * <p>Iteration 1 has no client registration endpoint. These are development fixtures: a real
 * deployment would register clients properly and would not ship a known secret.
 *
 * <p>The in-memory store is seeded unconditionally, because an empty in-memory store is unusable
 * and costs nothing to fill. The file store is seeded only when
 * {@code oauth2.file.persistence.seed-demo-clients=true}, because that file is the operator's
 * chosen source of truth and writing known-credential fixtures into it by default would be a
 * surprising thing for a server to do.
 */
@Configuration(proxyBeanMethods = false)
public class ClientSeedConfiguration {

    private static final Logger log = LoggerFactory.getLogger(ClientSeedConfiguration.class);

    /** Contains a space, '+', '%', '&', ':' and a non-ASCII character, for Appendix B testing. */
    private static final String SPECIAL_SECRET = "p@ss w+rd%&:é";

    /**
     * Conditioned on the property rather than on {@code @ConditionalOnBean(InMemoryClientRepository.class)}.
     * A bean condition is evaluated while the configuration classes are still being parsed, so it
     * only works when the repository happens to have been registered first — with the two adapters
     * behind {@code @ConditionalOnProperty} there is nothing to order them by. The same property
     * that selects the repository is what actually determines whether this bean applies.
     */
    @Bean
    @ConditionalOnProperty(prefix = "oauth2.persistence", name = "repository",
            havingValue = "inmemory", matchIfMissing = true)
    public ApplicationRunner seedInMemoryDemoClients(InMemoryClientRepository clients,
                                                     ClientSecretHasher hasher) {
        return args -> seedDemoClients(clients::add, "in-memory", hasher);
    }

    @Bean
    @ConditionalOnProperty(prefix = "oauth2.persistence", name = "repository", havingValue = "file")
    public ApplicationRunner seedFileDemoClients(FileClientRepository clients,
                                                 ClientSecretHasher hasher) {
        return args -> {
            if (clients.size() > 0) {
                log.info("Clients file already holds {} client(s); leaving it alone",
                        clients.size());
                return;
            }
            seedDemoClients(clients::add, "file", hasher);
        };
    }

    private static void seedDemoClients(Consumer<Client> register, String store,
                                        ClientSecretHasher hasher) {
        register.accept(Client.builder()
                .id(new ClientId("demo-basic"))
                .secretHash(hasher.hash("secret"))
                .type(ClientType.CONFIDENTIAL)
                .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                .registeredScopes(ScopeSet.of("read", "write"))
                .authMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build());

        register.accept(Client.builder()
                .id(new ClientId("demo-post"))
                .secretHash(hasher.hash("secret"))
                .type(ClientType.CONFIDENTIAL)
                .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                .registeredScopes(ScopeSet.of("read"))
                .authMethod(TokenEndpointAuthMethod.CLIENT_SECRET_POST)
                .build());

        register.accept(Client.builder()
                .id(new ClientId("demo-special"))
                .secretHash(hasher.hash(SPECIAL_SECRET))
                .type(ClientType.CONFIDENTIAL)
                .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                .registeredScopes(ScopeSet.of("read"))
                .authMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build());

        log.info("Seeded 3 demo clients into the {} store", store);
    }
}
