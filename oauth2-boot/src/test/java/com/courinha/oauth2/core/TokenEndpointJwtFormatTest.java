package com.courinha.oauth2.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The same endpoint with {@code oauth2.token.format=jwt} — which is the whole point of the
 * split adapter modules: the format changes, the domain and use case do not.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "oauth2.token.format=jwt")
class TokenEndpointJwtFormatTest {

    /** Matches the development default in application.properties. */
    private static final String SECRET = "dev-only-insecure-secret-change-me-32b";

    @LocalServerPort
    private int port;

    private RestTemplate rest;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        rest = new RestTemplate(new JdkClientHttpRequestFactory());
        rest.setUriTemplateHandler(new DefaultUriBuilderFactory("http://localhost:" + port));
        rest.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }
        });
    }

    private String requestToken() {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "client_credentials");
        parameters.add("scope", "read write");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder()
                .encodeToString("demo-basic:secret".getBytes(StandardCharsets.UTF_8)));

        ResponseEntity<String> response =
                rest.postForEntity("/oauth2/token", new HttpEntity<>(parameters, headers), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        return objectMapper.readTree(response.getBody()).get("access_token").asString();
    }

    private static JsonNode decode(String token, int index) throws Exception {
        return new ObjectMapper().readTree(Base64.getUrlDecoder().decode(token.split("\\.")[index]));
    }

    @Test
    void issuesAThreeSegmentJwt() throws Exception {
        String token = requestToken();

        assertThat(token.split("\\.")).hasSize(3);
        assertThat(decode(token, 0).get("alg").asString()).isEqualTo("HS256");
    }

    @Test
    void encodesTheClientAndScopesAsClaims() throws Exception {
        JsonNode claims = decode(requestToken(), 1);

        assertThat(claims.get("sub").asString()).isEqualTo("demo-basic");
        assertThat(claims.get("client_id").asString()).isEqualTo("demo-basic");
        assertThat(claims.get("scope").asString()).isEqualTo("read write");
        assertThat(claims.get("iss").asString()).isEqualTo("https://localhost:8080");
    }

    @Test
    void setsAnExpiryConsistentWithTheConfiguredLifetime() throws Exception {
        JsonNode claims = decode(requestToken(), 1);

        assertThat(claims.get("exp").asLong() - claims.get("iat").asLong()).isEqualTo(3600);
    }

    /** Recomputed from the secret, so the assertion does not lean on the production codec. */
    @Test
    void signsTheTokenWithHmacSha256() throws Exception {
        String token = requestToken();
        String[] parts = token.split("\\.");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));

        assertThat(Base64.getUrlDecoder().decode(parts[2]))
                .isEqualTo(mac.doFinal((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void stillReturnsTheStandardResponseMembers() {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "client_credentials");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder()
                .encodeToString("demo-basic:secret".getBytes(StandardCharsets.UTF_8)));

        ResponseEntity<String> response =
                rest.postForEntity("/oauth2/token", new HttpEntity<>(parameters, headers), String.class);
        JsonNode body = objectMapper.readTree(response.getBody());

        // Only the token *value* changes with the format; §5.1's members are unchanged.
        assertThat(body.get("token_type").asString()).isEqualTo("Bearer");
        assertThat(body.get("expires_in").asLong()).isEqualTo(3600);
        assertThat(body.get("scope").asString()).isEqualTo("read write");
        assertThat(response.getBody()).doesNotContain("refresh_token");
    }
}
