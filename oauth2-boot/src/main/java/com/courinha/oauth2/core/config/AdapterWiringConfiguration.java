package com.courinha.oauth2.core.config;

import com.courinha.oauth2.core.adapter.out.persistence.inmemory.InMemoryAccessTokenRepository;
import com.courinha.oauth2.core.adapter.out.persistence.inmemory.InMemoryClientRepository;
import com.courinha.oauth2.core.adapter.out.persistence.file.FileAccessTokenRepository;
import com.courinha.oauth2.core.adapter.out.persistence.file.FileClientRepository;
import com.courinha.oauth2.core.adapter.out.persistence.file.FileConfigs;
import com.courinha.oauth2.core.adapter.out.policy.fixed.FixedTokenLifetimeAdapter;
import com.courinha.oauth2.core.adapter.out.secret.bcrypt.BCryptClientSecretHasher;
import com.courinha.oauth2.core.adapter.out.time.system.SystemClockAdapter;
import com.courinha.oauth2.core.application.port.out.AccessTokenRepository;
import com.courinha.oauth2.core.application.port.out.ClientRepository;
import com.courinha.oauth2.core.application.port.out.ClientSecretHasher;
import com.courinha.oauth2.core.application.port.out.ClockPort;
import com.courinha.oauth2.core.application.port.out.TokenLifetimePort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Binds driven adapters to the ports they implement.
 *
 * <p>Each bean's return type is the <em>port</em>, not the adapter class, so nothing downstream
 * can depend on which implementation was chosen. Swapping an adapter is a change to this file
 * and the module dependency — never to the domain or the use case.
 *
 * <p>The concrete types are still exposed where a bean genuinely needs them: the in-memory
 * client repository is returned as itself because the seeder calls its adapter-only
 * {@code add} method.
 */
@Configuration(proxyBeanMethods = false)
public class AdapterWiringConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = "oauth2.persistence", name = "repository", havingValue = "inmemory", matchIfMissing = true)
    public InMemoryClientRepository inMemoryClientRepository() {
        return new InMemoryClientRepository();
    }

    @Bean
    @ConditionalOnProperty(prefix = "oauth2.persistence", name = "repository", havingValue = "file")
    public ClientRepository fileClientRepository(FileConfigs configs) {
        return new FileClientRepository(configs);
    }

    @Bean
    @ConditionalOnProperty(prefix = "oauth2.persistence", name = "repository", havingValue = "inmemory", matchIfMissing = true)
    public AccessTokenRepository accessTokenRepository() {
        return new InMemoryAccessTokenRepository();
    }

    @Bean
    @ConditionalOnProperty(prefix = "oauth2.persistence", name = "repository", havingValue = "file")
    public AccessTokenRepository fileAccessTokenRepository(FileConfigs configs) {
        return new FileAccessTokenRepository(configs);
    }

    @Bean
    public ClientSecretHasher clientSecretHasher() {
        return new BCryptClientSecretHasher();
    }

    @Bean
    public ClockPort clockPort() {
        return new SystemClockAdapter();
    }

    @Bean
    public TokenLifetimePort tokenLifetimePort(TokenProperties properties) {
        return new FixedTokenLifetimeAdapter(properties.getAccessTokenTtl());
    }
}
