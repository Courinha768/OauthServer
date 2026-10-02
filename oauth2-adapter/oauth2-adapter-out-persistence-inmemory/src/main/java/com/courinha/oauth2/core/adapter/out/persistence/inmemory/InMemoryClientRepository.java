package com.courinha.oauth2.core.adapter.out.persistence.inmemory;

import com.courinha.oauth2.core.application.port.out.ClientRepository;
import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A map-backed {@link ClientRepository}.
 *
 * <p>{@link #add} is deliberately not on the port: registering clients is an administrative
 * concern that no use case performs yet. A database adapter would gain the same operation
 * through its own interface, which is why the port stays narrow.
 */
public final class InMemoryClientRepository implements ClientRepository {

    /**
     * Keyed by the identifier's {@code String} rather than by {@link ClientId} itself:
     * {@code ClientId} is mutable and derives its {@code hashCode} from its value, so using it
     * as a key would let an in-place mutation orphan an entry.
     */
    private final ConcurrentMap<String, Client> clients = new ConcurrentHashMap<>();

    public void add(Client client) {
        clients.put(client.getId().getValue(), client);
    }

    @Override
    public Optional<Client> findByClientId(ClientId clientId) {
        return Optional.ofNullable(clients.get(clientId.getValue()));
    }

    public int size() {
        return clients.size();
    }
}
