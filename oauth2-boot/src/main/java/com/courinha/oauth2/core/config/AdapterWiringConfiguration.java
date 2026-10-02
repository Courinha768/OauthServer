package com.courinha.oauth2.core.config;

import com.courinha.oauth2.core.adapter.out.persistence.inmemory.InMemoryAccessTokenRepository;
import com.courinha.oauth2.core.adapter.out.persistence.inmemory.InMemoryClientRepository;
import com.courinha.oauth2.core.adapter.out.policy.fixed.FixedTokenLifetimeAdapter;
import com.courinha.oauth2.core.adapter.out.secret.bcrypt.BCryptClientSecretHasher;
import com.courinha.oauth2.core.adapter.out.time.system.SystemClockAdapter;
import com.courinha.oauth2.core.application.port.out.AccessTokenRepository;
import com.courinha.oauth2.core.application.port.out.ClientSecretHasher;
import com.courinha.oauth2.core.application.port.out.ClockPort;
import com.courinha.oauth2.core.application.port.out.TokenLifetimePort;
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
    public InMemoryClientRepository inMemoryClientRepository() {
        return new InMemoryClientRepository();
    }

    @Bean
    public AccessTokenRepository accessTokenRepository() {
        return new InMemoryAccessTokenRepository();
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
