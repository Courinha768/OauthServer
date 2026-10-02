package com.courinha.oauth2.core.application.fakes;

import com.courinha.oauth2.core.application.port.out.ClientRepository;
import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class FakeClientRepository implements ClientRepository {

    private final Map<String, Client> clients = new HashMap<>();

    public FakeClientRepository with(Client client) {
        clients.put(client.getId().getValue(), client);
        return this;
    }

    public static FakeClientRepository empty() {
        return new FakeClientRepository();
    }

    @Override
    public Optional<Client> findByClientId(ClientId clientId) {
        return Optional.ofNullable(clients.get(clientId.getValue()));
    }
}
