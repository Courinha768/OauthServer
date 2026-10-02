package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.domain.token.AccessToken;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The RFC 6749 §5.1 successful token response.
 *
 * <p>{@code scope} is always emitted. §5.1 makes it optional only when it is identical to what
 * the client requested and required otherwise, so sending it unconditionally satisfies both
 * branches without having to compare against the request.
 *
 * <p>There is no {@code refresh_token} member: §4.4.3 says one SHOULD NOT accompany this grant.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenResponseBody {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expires_in")
    private long expiresIn;

    @JsonProperty("scope")
    private String scope;

    public static TokenResponseBody from(AccessToken token) {
        return TokenResponseBody.builder()
                .accessToken(token.getValue())
                .tokenType(token.getTokenType().getWireValue())
                .expiresIn(token.expiresInSeconds())
                .scope(token.getScopes().asSpaceDelimited())
                .build();
    }

    /** Redacts the token: this response body carries a live credential. */
    @Override
    public String toString() {
        return "TokenResponseBody[accessToken=REDACTED, tokenType=%s, expiresIn=%d, scope=%s]"
                .formatted(tokenType, expiresIn, scope);
    }
}
