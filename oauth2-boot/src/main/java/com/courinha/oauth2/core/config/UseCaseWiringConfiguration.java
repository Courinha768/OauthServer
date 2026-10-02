package com.courinha.oauth2.core.config;

import com.courinha.oauth2.core.adapter.in.web.BasicAuthHeaderParser;
import com.courinha.oauth2.core.adapter.in.web.TokenRequestParser;
import com.courinha.oauth2.core.application.port.in.IssueClientCredentialsTokenUseCase;
import com.courinha.oauth2.core.application.port.out.AccessTokenGenerator;
import com.courinha.oauth2.core.application.port.out.AccessTokenRepository;
import com.courinha.oauth2.core.application.port.out.ClientRepository;
import com.courinha.oauth2.core.application.port.out.ClientSecretHasher;
import com.courinha.oauth2.core.application.port.out.ClockPort;
import com.courinha.oauth2.core.application.port.out.TokenLifetimePort;
import com.courinha.oauth2.core.application.service.ClientCredentialsTokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Assembles the use case from the ports it declares.
 *
 * <p>This constructor call is the only place the application service is instantiated, which is
 * what keeps it free of framework annotations and testable with plain fakes.
 */
@Configuration(proxyBeanMethods = false)
public class UseCaseWiringConfiguration {

    @Bean
    public IssueClientCredentialsTokenUseCase issueClientCredentialsTokenUseCase(
            ClientRepository clientRepository,
            AccessTokenRepository accessTokenRepository,
            AccessTokenGenerator accessTokenGenerator,
            ClientSecretHasher clientSecretHasher,
            ClockPort clockPort,
            TokenLifetimePort tokenLifetimePort) {

        return new ClientCredentialsTokenService(
                clientRepository,
                accessTokenRepository,
                accessTokenGenerator,
                clientSecretHasher,
                clockPort,
                tokenLifetimePort);
    }

    @Bean
    public TokenRequestParser tokenRequestParser() {
        return new TokenRequestParser(new BasicAuthHeaderParser());
    }
}
