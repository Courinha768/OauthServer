package com.courinha.oauth2.core.adapter.out.persistence.file;

import com.courinha.oauth2.core.application.port.out.ClientRepository;
import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;
import com.courinha.oauth2.core.domain.client.ClientType;
import com.courinha.oauth2.core.domain.client.GrantType;
import com.courinha.oauth2.core.domain.client.SecretHash;
import com.courinha.oauth2.core.domain.client.TokenEndpointAuthMethod;
import com.courinha.oauth2.core.domain.scope.Scope;
import com.courinha.oauth2.core.domain.scope.ScopeSet;
import tools.jackson.core.type.TypeReference;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * A JSON-file-backed {@link ClientRepository}.
 *
 * <p>Reads the whole file once at construction and keeps it in memory; every mutation rewrites
 * the file. That is fine for a client registry, which is small and changes rarely, and it is what
 * makes the file editable by hand — but each write is a full rewrite, so it is not a design for
 * a store that changes constantly.
 *
 * <p>Keyed by the identifier's {@code String} rather than by {@link ClientId} itself:
 * {@code ClientId} is mutable and derives its {@code hashCode} from its value, so using it as a
 * key would let an in-place mutation orphan an entry.
 *
 * <p>{@link #add} is deliberately not on the port: registering clients is an administrative
 * concern that no use case performs yet.
 */
public final class FileClientRepository implements ClientRepository {

    private static final String CLIENTS_PROPERTY = "clients-file-path";
    private static final String WHAT = "clients";

    private static final TypeReference<List<ClientRecord>> CLIENTS_TYPE = new TypeReference<>() {
    };

    private final FileConfigs configs;
    private final ConcurrentMap<String, Client> clients = new ConcurrentHashMap<>();

    public FileClientRepository(FileConfigs configs) {
        this.configs = Objects.requireNonNull(configs, "configs");
        loadFromDisk();
    }

    public synchronized void add(Client client) {
        clients.put(client.getId().getValue(), client);
        persist();
    }

    @Override
    public Optional<Client> findByClientId(ClientId clientId) {
        return Optional.ofNullable(clients.get(clientId.getValue()));
    }

    public int size() {
        return clients.size();
    }

    private Path filePath() {
        return JsonFileStore.resolve(configs.getClientsFilePath(), CLIENTS_PROPERTY);
    }

    private void loadFromDisk() {
        for (ClientRecord record : JsonFileStore.read(filePath(), CLIENTS_TYPE, WHAT)) {
            Client client = toDomain(record);
            clients.put(client.getId().getValue(), client);
        }
    }

    private void persist() {
        JsonFileStore.write(filePath(), clients.values().stream()
                .map(FileClientRepository::toRecord)
                .toList(), WHAT);
    }

    /**
     * The enum members are written as their RFC 6749 wire spellings rather than as the Java
     * constant names or by way of {@code toString()}. Jackson would happily pick one of those,
     * but then the file format would depend on a framework default and on {@code toString()}
     * overrides that live in the domain module — so renaming a constant for readability would
     * silently change the format and orphan every file already written.
     */
    private static ClientRecord toRecord(Client client) {
        return new ClientRecord(
                client.getId().getValue(),
                client.getSecretHash() == null ? null : client.getSecretHash().getValue(),
                client.getType().name(),
                client.getGrantTypes().stream().map(GrantType::getWireValue).toList(),
                client.getRegisteredScopes().getScopes().stream().map(Scope::getValue).toList(),
                client.getAuthMethod().getWireValue());
    }

    private static Client toDomain(ClientRecord record) {
        Objects.requireNonNull(record.id(), "record.id");
        Objects.requireNonNull(record.type(), "record.type");
        Objects.requireNonNull(record.grantTypes(), "record.grantTypes");
        Objects.requireNonNull(record.registeredScopes(), "record.registeredScopes");
        Objects.requireNonNull(record.authMethod(), "record.authMethod");

        return Client.builder()
                .id(new ClientId(record.id()))
                .secretHash(record.secretHash() == null ? null : new SecretHash(record.secretHash()))
                .type(clientType(record.type()))
                .grantTypes(record.grantTypes().stream()
                        .map(FileClientRepository::grantType)
                        .collect(Collectors.toCollection(LinkedHashSet::new)))
                .registeredScopes(ScopeSet.of(record.registeredScopes().toArray(String[]::new)))
                .authMethod(authMethod(record.authMethod()))
                .build();
    }

    private static ClientType clientType(String value) {
        try {
            return ClientType.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw unknown("client type", value, e);
        }
    }

    private static GrantType grantType(String value) {
        return GrantType.fromWire(value)
                .orElseThrow(() -> unknown("grant type", value, null));
    }

    private static TokenEndpointAuthMethod authMethod(String value) {
        return TokenEndpointAuthMethod.fromWire(value)
                .orElseThrow(() -> unknown("token endpoint auth method", value, null));
    }

    private static IllegalStateException unknown(String field, String value, Throwable cause) {
        return new IllegalStateException(
                "Unknown %s '%s' in the clients file".formatted(field, value), cause);
    }

    /** The on-disk shape. Kept separate from {@link Client} so storage never shapes the model. */
    record ClientRecord(String id,
                        String secretHash,
                        String type,
                        List<String> grantTypes,
                        List<String> registeredScopes,
                        String authMethod) {

        ClientRecord {
            grantTypes = grantTypes == null ? null : new ArrayList<>(grantTypes);
        }
    }
}
