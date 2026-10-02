package com.courinha.oauth2.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Composition root for the authorization server.
 *
 * <p>Deliberately kept in {@code com.courinha.oauth2.core} rather than a {@code boot} subpackage:
 * component scanning starts here, and the web and persistence adapters live under
 * {@code com.courinha.oauth2.core.adapter}. Moving this class down a level would silently stop
 * the adapters from being picked up, and every endpoint would 404 with a green build.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class Oauth2CoreApplication {

    private static final Logger log = LoggerFactory.getLogger(Oauth2CoreApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(Oauth2CoreApplication.class, args);
        log.info("OAuth2 authorization server started");
    }
}
