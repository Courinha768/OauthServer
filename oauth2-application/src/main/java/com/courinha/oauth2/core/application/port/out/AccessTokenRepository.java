package com.courinha.oauth2.core.application.port.out;

import com.courinha.oauth2.core.domain.token.AccessToken;

/**
 * Stores issued access tokens.
 *
 * <p>Tokens are persisted regardless of whether the generator produced an opaque string or a
 * self-contained JWT. For an opaque token this is what makes it resolvable at all; for a JWT it
 * is redundant for validation but keeps revocation uniform across both formats.
 */
public interface AccessTokenRepository {

    void save(AccessToken token);
}
