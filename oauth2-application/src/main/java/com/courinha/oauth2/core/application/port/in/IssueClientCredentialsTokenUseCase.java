package com.courinha.oauth2.core.application.port.in;

import com.courinha.oauth2.core.domain.error.OAuth2Exception;
import com.courinha.oauth2.core.domain.token.AccessToken;

/**
 * The inbound port for RFC 6749 §4.4: exchange client credentials for an access token.
 */
@FunctionalInterface
public interface IssueClientCredentialsTokenUseCase {

    /**
     * Issues an access token to an authenticated confidential client.
     *
     * <p>Returns the domain token rather than a wire representation; the adapter derives
     * {@code expires_in} and the JSON shape from it.
     *
     * @throws OAuth2Exception with the §5.2 code appropriate to the failure
     */
    AccessToken issue(ClientCredentialsCommand command);
}
