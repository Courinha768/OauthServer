package com.courinha.oauth2.core.application.port.out;

import com.courinha.oauth2.core.domain.client.Client;
import com.courinha.oauth2.core.domain.client.ClientId;

import java.util.Optional;

/**
 * Looks up registered clients.
 *
 * <p>Backed by an in-memory map today and by a database later; because callers only ever see
 * this interface, that swap touches no domain or application code.
 */
public interface ClientRepository {

    Optional<Client> findByClientId(ClientId clientId);
}
