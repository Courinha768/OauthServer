package com.courinha.oauth2.core.adapter.out.persistence.file;

import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.client.ClientType;
import com.courinha.oauth2.core.domain.client.GrantType;
import com.courinha.oauth2.core.domain.client.SecretHash;
import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Plain JUnit — no Spring context. The adapter only needs {@code FileConfigs} populated, which a
 * setter does just as well as the Binder does.
 */
class FileClientRepositoryTest {

    @TempDir
    Path tempDir;

    private static Client demoClient() {
        return Client.builder()
                .id(new ClientId("demo-basic"))
                .secretHash(new SecretHash("$2a$10$stored-hash"))
                .type(ClientType.CONFIDENTIAL)
                .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                .registeredScopes(ScopeSet.of("read", "write"))
                .authMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build();
    }

    private FileConfigs configsFor(Path clientsFile) {
        FileConfigs configs = new FileConfigs();
        configs.setClientsFilePath(clientsFile.toString());
        configs.setAccessTokensFilePath(tempDir.resolve("access-tokens.json").toString());
        return configs;
    }

    private Path clientsFile() {
        return tempDir.resolve("clients.json");
    }

    @Test
    void aMissingFileIsAnEmptyStoreRatherThanAnError() {
        FileClientRepository repository = new FileClientRepository(configsFor(clientsFile()));

        assertThat(repository.size()).isZero();
        assertThat(repository.findByClientId(new ClientId("demo-basic"))).isEmpty();
        assertThat(clientsFile()).doesNotExist();
    }

    @Test
    void aClientSurvivesAReconstructionOfTheRepository() {
        FileClientRepository first = new FileClientRepository(configsFor(clientsFile()));
        first.add(demoClient());

        FileClientRepository second = new FileClientRepository(configsFor(clientsFile()));
        Optional<Client> reloaded = second.findByClientId(new ClientId("demo-basic"));

        assertThat(reloaded).isPresent();
        Client client = reloaded.orElseThrow();
        assertThat(client.getId().getValue()).isEqualTo("demo-basic");
        assertThat(client.getType()).isEqualTo(ClientType.CONFIDENTIAL);
        assertThat(client.getAuthMethod()).isEqualTo(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        assertThat(client.getGrantTypes()).containsExactly(GrantType.CLIENT_CREDENTIALS);
        assertThat(client.getRegisteredScopes().asSpaceDelimited()).isEqualTo("read write");
        assertThat(client.getSecretHash().getValue()).isEqualTo("$2a$10$stored-hash");
        assertThat(client.isGrantedFor(GrantType.CLIENT_CREDENTIALS)).isTrue();
    }

    @Test
    void scopeOrderIsPreservedAcrossAReload() {
        FileClientRepository first = new FileClientRepository(configsFor(clientsFile()));
        first.add(Client.builder()
                .id(new ClientId("ordered"))
                .secretHash(new SecretHash("$2a$10$stored-hash"))
                .type(ClientType.CONFIDENTIAL)
                .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                .registeredScopes(ScopeSet.of("write", "read", "admin"))
                .authMethod(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC)
                .build());

        FileClientRepository second = new FileClientRepository(configsFor(clientsFile()));

        assertThat(second.findByClientId(new ClientId("ordered")).orElseThrow()
                .getRegisteredScopes().asSpaceDelimited()).isEqualTo("write read admin");
    }

    @Test
    void aPublicClientRoundTripsWithoutASecret() {
        FileClientRepository first = new FileClientRepository(configsFor(clientsFile()));
        first.add(Client.builder()
                .id(new ClientId("public-one"))
                .type(ClientType.PUBLIC)
                .grantTypes(EnumSet.of(GrantType.CLIENT_CREDENTIALS))
                .registeredScopes(ScopeSet.of("read"))
                .authMethod(TokenEndpointAuthMethod.NONE)
                .build());

        FileClientRepository second = new FileClientRepository(configsFor(clientsFile()));

        assertThat(second.findByClientId(new ClientId("public-one")).orElseThrow().getSecretHash())
                .isNull();
    }

    @Test
    void missingParentDirectoriesAreCreatedOnFirstWrite() {
        Path nested = tempDir.resolve("deeply").resolve("nested").resolve("clients.json");

        new FileClientRepository(configsFor(nested)).add(demoClient());

        assertThat(nested).exists();
    }

    @Test
    void registeringTheSameClientTwiceReplacesItRatherThanAppending() throws IOException {
        FileClientRepository repository = new FileClientRepository(configsFor(clientsFile()));
        repository.add(demoClient());
        repository.add(demoClient());

        FileClientRepository reloaded = new FileClientRepository(configsFor(clientsFile()));

        assertThat(reloaded.size()).isEqualTo(1);
        assertThat(Files.readString(clientsFile())).containsOnlyOnce("\"demo-basic\"");
    }

    @Test
    void onlyTheSecretHashEverReachesTheFile() throws IOException {
        FileClientRepository repository = new FileClientRepository(configsFor(clientsFile()));
        repository.add(demoClient());

        String contents = Files.readString(clientsFile());

        assertThat(contents).contains("$2a$10$stored-hash");
        // The model never holds a plaintext secret, so there is nothing else that could leak —
        // this asserts the shape stays that way.
        assertThat(contents).contains("\"secretHash\"");
        assertThat(contents).doesNotContain("clientSecret", "\"secret\"");
    }

    @Test
    void aFilePathThatIsBlankFailsWithThePropertyName() {
        FileConfigs configs = configsFor(clientsFile());
        configs.setClientsFilePath("   ");

        assertThatThrownBy(() -> new FileClientRepository(configs))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("oauth2.file.persistence.clients-file-path");
    }

    @Test
    void aMalformedFileFailsLoudlyInsteadOfSilentlyStartingEmpty() throws IOException {
        Files.writeString(clientsFile(), "{ this is not json");

        assertThatThrownBy(() -> new FileClientRepository(configsFor(clientsFile())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("clients.json")
                .hasMessageContaining("Failed to read clients");
    }

    @Test
    void enumsAreWrittenAsTheirRfcWireSpellings() throws IOException {
        FileClientRepository repository = new FileClientRepository(configsFor(clientsFile()));
        repository.add(demoClient());

        // Not the Java constant names, and not whatever toString() happens to return: the file
        // format must not move if a constant is renamed.
        assertThat(Files.readString(clientsFile()))
                .contains("\"client_credentials\"")
                .contains("\"client_secret_basic\"")
                .contains("\"CONFIDENTIAL\"")
                .doesNotContain("\"CLIENT_CREDENTIALS\"")
                .doesNotContain("\"CLIENT_SECRET_BASIC\"");
    }

    @Test
    void aFileWrittenInTheWireSpellingIsReadBackExactly() throws IOException {
        Files.writeString(clientsFile(), """
                [ { "id" : "hand-written", "secretHash" : "$2a$10$h", "type" : "CONFIDENTIAL",
                    "grantTypes" : [ "client_credentials", "refresh_token" ],
                    "registeredScopes" : [ "read" ],
                    "authMethod" : "client_secret_post" } ]
                """);

        Client client = new FileClientRepository(configsFor(clientsFile()))
                .findByClientId(new ClientId("hand-written")).orElseThrow();

        assertThat(client.getType()).isEqualTo(ClientType.CONFIDENTIAL);
        assertThat(client.getAuthMethod()).isEqualTo(TokenEndpointAuthMethod.CLIENT_SECRET_POST);
        assertThat(client.getGrantTypes())
                .containsExactlyInAnyOrder(GrantType.CLIENT_CREDENTIALS, GrantType.REFRESH_TOKEN);
    }

    @Test
    void anUnknownClientTypeFailsRatherThanDroppingTheClient() throws IOException {
        Files.writeString(clientsFile(), """
                [ { "id": "x", "secretHash": "$2a$10$h", "type": "NOT_A_CLIENT_TYPE",
                    "grantTypes": [], "registeredScopes": [], "authMethod": "client_secret_basic" } ]
                """);

        assertThatThrownBy(() -> new FileClientRepository(configsFor(clientsFile())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown client type")
                .hasMessageContaining("NOT_A_CLIENT_TYPE");
    }

    @Test
    void anUnknownGrantTypeFailsRatherThanProducingAClientThatCannotBeUsed() throws IOException {
        Files.writeString(clientsFile(), """
                [ { "id": "x", "secretHash": "$2a$10$h", "type": "CONFIDENTIAL",
                    "grantTypes": [ "client_credentials", "made_up_grant" ],
                    "registeredScopes": [ "read" ], "authMethod": "client_secret_basic" } ]
                """);

        assertThatThrownBy(() -> new FileClientRepository(configsFor(clientsFile())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown grant type")
                .hasMessageContaining("made_up_grant");
    }

    @Test
    void theFileIsCreatedOwnerOnlyWherePosixPermissionsExist() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
                "POSIX permissions are not available on this platform");

        new FileClientRepository(configsFor(clientsFile())).add(demoClient());

        assertThat(Files.getPosixFilePermissions(clientsFile()))
                .containsExactlyInAnyOrder(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    }

    @Test
    void anExistingFilesPermissionsAreLeftAlone() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
                "POSIX permissions are not available on this platform");
        Files.writeString(clientsFile(), "[]");
        Files.setPosixFilePermissions(clientsFile(),
                PosixFilePermissions.fromString("rw-r-----"));

        new FileClientRepository(configsFor(clientsFile())).add(demoClient());

        assertThat(Files.getPosixFilePermissions(clientsFile()))
                .containsExactlyInAnyOrder(PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_READ);
    }
}
