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
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end against the real wiring: real repository, real BCrypt hashing, the opaque generator
 * and the seeded clients. The token endpoint is exercised exactly as a client would.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TokenEndpointEndToEndTest {

    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String SPECIAL_SECRET = "p@ss w+rd%&:é";

    @LocalServerPort
    private int port;

    /**
     * A plain {@code RestTemplate}, with its error handler disabled so that a 4xx response is
     * returned to the test rather than thrown. Asserting on the status and body is the whole
     * point of the error cases below.
     */
    private RestTemplate rest;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        // The java.net.http-backed factory rather than the JDK's HttpURLConnection one: the
        // latter does not expose the response body on a 401, which would make the
        // invalid_client assertions vacuous.
        rest = new RestTemplate(new JdkClientHttpRequestFactory());
        rest.setUriTemplateHandler(new DefaultUriBuilderFactory("http://localhost:" + port));
        rest.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }
        });
    }

    private JsonNode bodyOf(ResponseEntity<String> response) {
        return objectMapper.readTree(response.getBody());
    }

    private static MultiValueMap<String, String> form(String scope) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "client_credentials");
        if (scope != null) {
            parameters.add("scope", scope);
        }
        return parameters;
    }

    private ResponseEntity<String> post(MultiValueMap<String, String> parameters, HttpHeaders headers) {
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return rest.postForEntity(TOKEN_ENDPOINT, new HttpEntity<>(parameters, headers), String.class);
    }

    private static HttpHeaders basicAuth(String formEncodedClientId, String formEncodedSecret) {
        HttpHeaders headers = new HttpHeaders();
        String credentials = formEncodedClientId + ":" + formEncodedSecret;
        headers.set(HttpHeaders.AUTHORIZATION,
                "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
        return headers;
    }

    @Test
    void issuesAnOpaqueTokenForValidBasicCredentials() {
        ResponseEntity<String> response = post(form("read"), basicAuth("demo-basic", "secret"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode body = bodyOf(response);
        assertThat(body.get("access_token").asString()).isNotBlank();
        assertThat(body.get("token_type").asString()).isEqualTo("Bearer");
        assertThat(body.get("expires_in").asLong()).isEqualTo(3600);
        assertThat(body.get("scope").asString()).isEqualTo("read");
    }

    @Test
    void sendsTheCacheHeadersTheRfcRequires() {
        ResponseEntity<String> response = post(form("read"), basicAuth("demo-basic", "secret"));

        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        assertThat(response.getHeaders().getFirst(HttpHeaders.PRAGMA)).isEqualTo("no-cache");
    }

    @Test
    void neverReturnsARefreshToken() {
        // §4.4.3: a refresh token SHOULD NOT accompany the client credentials grant.
        ResponseEntity<String> response = post(form("read"), basicAuth("demo-basic", "secret"));

        assertThat(response.getBody()).doesNotContain("refresh_token");
    }

    @Test
    void echoesScopeWhenTheClientOmitsIt() {
        ResponseEntity<String> response = post(form(null), basicAuth("demo-basic", "secret"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(bodyOf(response).get("scope").asString()).isEqualTo("read write");
    }

    @Test
    void acceptsCredentialsInTheBody() {
        MultiValueMap<String, String> parameters = form("read");
        parameters.add("client_id", "demo-post");
        parameters.add("client_secret", "secret");

        ResponseEntity<String> response = post(parameters, new HttpHeaders());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(bodyOf(response).get("access_token").asString()).isNotBlank();
    }

    @Test
    void issuesADifferentTokenEachTime() {
        String first = bodyOf(post(form("read"), basicAuth("demo-basic", "secret"))).get("access_token").asString();
        String second = bodyOf(post(form("read"), basicAuth("demo-basic", "secret"))).get("access_token").asString();

        assertThat(first).isNotEqualTo(second);
    }

    // --- Appendix B -------------------------------------------------------------------------

    /**
     * The highest-value conformance test here: this client's secret contains a space, {@code @},
     * {@code +}, {@code %}, {@code &}, {@code :} and a non-ASCII character, so it only
     * authenticates if the Basic header is form-decoded as well as Base64-decoded.
     */
    @Test
    void authenticatesASecretNeedingAppendixBEncoding() {
        ResponseEntity<String> response = post(form("read"), basicAuth("demo-special", encodePerAppendixB(SPECIAL_SECRET)));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(bodyOf(response).get("access_token").asString()).isNotBlank();
    }

    // --- Error cases ------------------------------------------------------------------------

    @Test
    void rejectsAWrongSecretWith401AndAChallenge() {
        ResponseEntity<String> response = post(form(null), basicAuth("demo-basic", "wrong"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .startsWith("Basic realm=");
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("invalid_client");
    }

    @Test
    void doesNotChallengeWhenCredentialsWereInTheBody() {
        MultiValueMap<String, String> parameters = form(null);
        parameters.add("client_id", "demo-post");
        parameters.add("client_secret", "wrong");

        ResponseEntity<String> response = post(parameters, new HttpHeaders());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isNull();
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("invalid_client");
    }

    @Test
    void doesNotDistinguishAnUnknownClientFromAWrongSecret() {
        String unknownClient = post(form(null), basicAuth("nobody", "secret")).getBody();
        String wrongSecret = post(form(null), basicAuth("demo-basic", "wrong")).getBody();

        assertThat(unknownClient).isEqualTo(wrongSecret);
    }

    @Test
    void rejectsScopeEscalation() {
        ResponseEntity<String> response = post(form("read admin"), basicAuth("demo-basic", "secret"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("invalid_scope");
    }

    @Test
    void rejectsAGrantTypeTheServerDoesNotImplement() {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "authorization_code");

        ResponseEntity<String> response = post(parameters, basicAuth("demo-basic", "secret"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("unsupported_grant_type");
    }

    @Test
    void rejectsARepeatedParameter() {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "client_credentials");
        parameters.add("grant_type", "client_credentials");

        ResponseEntity<String> response = post(parameters, basicAuth("demo-basic", "secret"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("invalid_request");
    }

    @Test
    void rejectsBothAuthenticationMethodsAtOnce() {
        MultiValueMap<String, String> parameters = form(null);
        parameters.add("client_secret", "secret");

        ResponseEntity<String> response = post(parameters, basicAuth("demo-basic", "secret"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("invalid_request");
    }

    @Test
    void rejectsCredentialsInTheQueryString() {
        ResponseEntity<String> response = rest.postForEntity(
                TOKEN_ENDPOINT + "?client_id=demo-basic",
                new HttpEntity<>(form(null), defaultFormHeaders()),
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("invalid_request");
    }

    @Test
    void rejectsARequestWithNoGrantType() {
        ResponseEntity<String> response = post(new LinkedMultiValueMap<>(), basicAuth("demo-basic", "secret"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("invalid_request");
    }

    @Test
    void rejectsANonFormContentType() {
        HttpHeaders headers = basicAuth("demo-basic", "secret");
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<String> response = rest.postForEntity(
                TOKEN_ENDPOINT, new HttpEntity<>("{\"grant_type\":\"client_credentials\"}", headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(bodyOf(response).get("error").asString()).isEqualTo("invalid_request");
    }

    @Test
    void rejectsGetOnTheTokenEndpoint() {
        ResponseEntity<String> response = rest.getForEntity(TOKEN_ENDPOINT, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
    }

    @Test
    void errorResponsesAlsoCarryTheCacheHeaders() {
        ResponseEntity<String> response = post(form(null), basicAuth("demo-basic", "wrong"));

        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        assertThat(response.getHeaders().getFirst(HttpHeaders.PRAGMA)).isEqualTo("no-cache");
    }

    private static HttpHeaders defaultFormHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

    /** The client side of RFC 6749 Appendix B, so the test encodes rather than hard-codes. */
    private static String encodePerAppendixB(String value) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int unsigned = b & 0xFF;
            boolean unreserved = (unsigned >= 'A' && unsigned <= 'Z')
                    || (unsigned >= 'a' && unsigned <= 'z')
                    || (unsigned >= '0' && unsigned <= '9')
                    || unsigned == '-' || unsigned == '_' || unsigned == '.' || unsigned == '~';
            if (unsigned == ' ') {
                encoded.append('+');
            } else if (unreserved) {
                encoded.append((char) unsigned);
            } else {
                encoded.append("%%%02X".formatted(unsigned));
            }
        }
        return encoded.toString();
    }
}
