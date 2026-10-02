package com.courinha.oauth2.core.adapter.out.persistence.file;

import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import com.courinha.oauth2.core.domain.token.AccessToken;
import com.courinha.oauth2.core.domain.token.TokenType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FileAccessTokenRepositoryTest {

    @TempDir
    Path tempDir;

    /** A full nine digits of nanos, to prove the text encoding is not quietly truncated. */
    private static final Instant ISSUED_AT = Instant.parse("2026-10-02T10:15:30.123456789Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-10-02T11:15:30.123456789Z");

    private static AccessToken token(String value) {
        return AccessToken.builder()
                .value(value)
                .clientId(new ClientId("demo-basic"))
                .scopes(ScopeSet.of("read", "write"))
                .tokenType(TokenType.BEARER)
                .issuedAt(ISSUED_AT)
                .expiresAt(EXPIRES_AT)
                .build();
    }

    private FileConfigs configsFor(Path tokensFile) {
        FileConfigs configs = new FileConfigs();
        configs.setAccessTokensFilePath(tokensFile.toString());
        configs.setClientsFilePath(tempDir.resolve("clients.json").toString());
        return configs;
    }

    private Path tokensFile() {
        return tempDir.resolve("access-tokens.json");
    }

    @Test
    void aMissingFileIsAnEmptyStoreRatherThanAnError() {
        FileAccessTokenRepository repository =
                new FileAccessTokenRepository(configsFor(tokensFile()));

        assertThat(repository.size()).isZero();
        assertThat(repository.findByValue("anything")).isEmpty();
        assertThat(tokensFile()).doesNotExist();
    }

    @Test
    void aTokenSurvivesAReconstructionOfTheRepository() {
        FileAccessTokenRepository first = new FileAccessTokenRepository(configsFor(tokensFile()));
        first.save(token("opaque-token-value"));

        FileAccessTokenRepository second = new FileAccessTokenRepository(configsFor(tokensFile()));
        Optional<AccessToken> reloaded = second.findByValue("opaque-token-value");

        assertThat(reloaded).isPresent();
        AccessToken stored = reloaded.orElseThrow();
        assertThat(stored.getClientId().getValue()).isEqualTo("demo-basic");
        assertThat(stored.getScopes().asSpaceDelimited()).isEqualTo("read write");
        assertThat(stored.getTokenType()).isEqualTo(TokenType.BEARER);
        assertThat(stored.getIssuedAt()).isEqualTo(ISSUED_AT);
        assertThat(stored.getExpiresAt()).isEqualTo(EXPIRES_AT);
        assertThat(stored.expiresInSeconds()).isEqualTo(3600);
    }

    @Test
    void savingTheSameValueTwiceReplacesRatherThanDuplicating() {
        FileAccessTokenRepository repository =
                new FileAccessTokenRepository(configsFor(tokensFile()));
        repository.save(token("same-value"));
        repository.save(token("same-value"));

        assertThat(new FileAccessTokenRepository(configsFor(tokensFile())).size()).isEqualTo(1);
    }

    @Test
    void distinctTokensAllSurviveAReload() {
        FileAccessTokenRepository repository =
                new FileAccessTokenRepository(configsFor(tokensFile()));
        repository.save(token("first"));
        repository.save(token("second"));
        repository.save(token("third"));

        FileAccessTokenRepository reloaded = new FileAccessTokenRepository(configsFor(tokensFile()));

        assertThat(reloaded.size()).isEqualTo(3);
        assertThat(reloaded.findByValue("second")).isPresent();
    }

    @Test
    void instantsAreStoredAsReadableIsoTextRatherThanEpochNumbers() throws IOException {
        new FileAccessTokenRepository(configsFor(tokensFile())).save(token("readable"));

        assertThat(Files.readString(tokensFile()))
                .contains("2026-10-02T10:15:30.123456789Z")
                // The RFC 6750 wire spelling, not the Java constant name.
                .contains("\"Bearer\"")
                .doesNotContain("\"BEARER\"");
    }

    @Test
    void aFileWrittenInTheWireSpellingIsReadBackExactly() throws IOException {
        Files.writeString(tokensFile(), """
                [ { "value" : "hand-written", "clientId" : "demo-basic", "scopes" : [ "read" ],
                    "tokenType" : "Bearer",
                    "issuedAt" : "2026-10-02T10:15:30Z", "expiresAt" : "2026-10-02T11:15:30Z" } ]
                """);

        AccessToken stored = new FileAccessTokenRepository(configsFor(tokensFile()))
                .findByValue("hand-written").orElseThrow();

        assertThat(stored.getTokenType()).isEqualTo(TokenType.BEARER);
        assertThat(stored.getScopes().asSpaceDelimited()).isEqualTo("read");
    }

    @Test
    void anUnknownTokenTypeFailsRatherThanYieldingATokenThatCannotBePresented() throws IOException {
        Files.writeString(tokensFile(), """
                [ { "value" : "x", "clientId" : "demo-basic", "scopes" : [ "read" ],
                    "tokenType" : "MAC",
                    "issuedAt" : "2026-10-02T10:15:30Z", "expiresAt" : "2026-10-02T11:15:30Z" } ]
                """);

        assertThatThrownBy(() -> new FileAccessTokenRepository(configsFor(tokensFile())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown token type")
                .hasMessageContaining("MAC");
    }

    @Test
    void aFilePathThatIsBlankFailsWithThePropertyName() {
        FileConfigs configs = configsFor(tokensFile());
        configs.setAccessTokensFilePath("");

        assertThatThrownBy(() -> new FileAccessTokenRepository(configs))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("oauth2.file.persistence.access-tokens-file-path");
    }

    @Test
    void aMalformedFileFailsLoudlyInsteadOfSilentlyStartingEmpty() throws IOException {
        Files.writeString(tokensFile(), "not json at all");

        assertThatThrownBy(() -> new FileAccessTokenRepository(configsFor(tokensFile())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("access-tokens.json")
                .hasMessageContaining("Failed to read access tokens");
    }
}
