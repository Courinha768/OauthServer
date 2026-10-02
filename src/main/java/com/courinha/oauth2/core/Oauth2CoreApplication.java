package com.courinha.oauth2.core;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@Slf4j
@SpringBootApplication
public class Oauth2CoreApplication {

    static void main(String[] args) {
        SpringApplication.run(Oauth2CoreApplication.class, args);
    }

    @PostConstruct
    public void init() {
        log.warn("Hello World");
    }

}
