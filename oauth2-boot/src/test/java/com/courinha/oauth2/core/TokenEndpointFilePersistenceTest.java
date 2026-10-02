package com.courinha.oauth2.core;

import com.courinha.oauth2.core.adapter.out.persistence.file.FileAccessTokenRepository;
import com.courinha.oauth2.core.adapter.out.persistence.file.FileClientRepository;
import com.courinha.oauth2.core.application.port.out.AccessTokenRepository;
import com.courinha.oauth2.core.application.port.out.ClientRepository;
import org.junit.jupiter.api.AfterAll;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The same endpoint as {@link TokenEndpointEndToEndTest}, but with the file adapters wired in
 * instead of the in-memory ones — and with the demo clients seeded into the file, since an empty
 * client registry would make every request 401 and prove nothing.
 *
 * <p>The temp directory is created in a static initializer rather than with a static
 * {@code @TempDir}: {@code @DynamicPropertySource} runs while the context is being prepared, and
 * there is no ordering guarantee that would have JUnit populate the field first.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TokenEndpointFilePersistenceTest {

    private static final Path DATA_DIR = createDataDir();
    private static final Path CLIENTS_FILE = DATA_DIR.resolve("clients.json");
    private static final Path TOKENS_FILE = DATA_DIR.resolve("access-tokens.json");

    @LocalServerPort
    private int port;

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private RestTemplate rest;

    private static Path createDataDir() {
        try {
            return Files.createTempDirectory("oauth2-file-persistence");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @DynamicPropertySource
    static void filePersistenceProperties(DynamicPropertyRegistry registry) {
        registry.add("oauth2.persistence.repository", () -> "file");
        registry.add("oauth2.file.persistence.clients-file-path", CLIENTS_FILE::toString);
        registry.add("oauth2.file.persistence.access-tokens-file-path", TOKENS_FILE::toString);
        registry.add("oauth2.file.persistence.seed-demo-clients", () -> "true");
    }

    @AfterAll
    static void deleteDataDir() throws IOException {
        if (!Files.exists(DATA_DIR)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(DATA_DIR)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private RestTemplate rest() {
        if (rest == null) {
            rest = new RestTemplate(new JdkClientHttpRequestFactory());
            rest.setUriTemplateHandler(new DefaultUriBuilderFactory("http://localhost:" + port));
            rest.setErrorHandler(new ResponseErrorHandler() {
                @Override
                public boolean hasError(ClientHttpResponse response) {
                    return false;
                }
            });
        }
        return rest;
    }

    @Test
    void theFileAdaptersAreTheOnesWiredIn() {
        assertThat(clientRepository).isInstanceOf(FileClientRepository.class);
        assertThat(accessTokenRepository).isInstanceOf(FileAccessTokenRepository.class);
    }

    @Test
    void theSeededClientsReachedTheFile() throws IOException {
        assertThat(Files.readString(CLIENTS_FILE))
                .contains("demo-basic")
                .contains("demo-post")
                .contains("demo-special")
                .contains("secretHash");
    }

    @Test
    void issuesATokenAndWritesItToTheTokensFile() throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(
                "demo-basic:secret".getBytes(StandardCharsets.UTF_8)));

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "client_credentials");
        parameters.add("scope", "read");

        ResponseEntity<String> response = rest().postForEntity(
                "/oauth2/token", new HttpEntity<>(parameters, headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = objectMapper.readTree(response.getBody()).get("access_token").asString();

        // The whole point of the file store: an opaque token is resolvable after a restart, which
        // means it has to be on disk before the response is written.
        assertThat(Files.readString(TOKENS_FILE))
                .contains(token)
                .contains("demo-basic")
                .contains("Bearer");
    }

    @Test
    void aWrongSecretIsStillRejected() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(
                "demo-basic:wrong".getBytes(StandardCharsets.UTF_8)));

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "client_credentials");

        ResponseEntity<String> response = rest().postForEntity(
                "/oauth2/token", new HttpEntity<>(parameters, headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(objectMapper.readTree(response.getBody()).get("error").asString())
                .isEqualTo("invalid_client");
    }
}
