package com.courinha.oauth2.core.adapter.in.web;

import com.courinha.oauth2.core.domain.error.OAuth2ErrorCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RFC 6749 §5.2: errors are HTTP 400, except that {@code invalid_client} MUST be 401 with a
 * matching {@code WWW-Authenticate} when the client used the {@code Authorization} header.
 */
class OAuth2ErrorHttpMapperTest {

    @ParameterizedTest
    @EnumSource(OAuth2ErrorCode.class)
    void everyCodeMapsToAClientErrorWithoutAChallengeByDefault(OAuth2ErrorCode code) {
        assertThat(OAuth2ErrorHttpMapper.statusFor(code, false))
                .isEqualTo(HttpStatus.BAD_REQUEST);

        assertThat(OAuth2ErrorHttpMapper.challengeFor(code, false)).isEmpty();
    }

    @Test
    void invalidClientIs401WithAChallengeWhenTheAuthorizationHeaderWasUsed() {
        assertThat(OAuth2ErrorHttpMapper.statusFor(OAuth2ErrorCode.INVALID_CLIENT, true))
                .isEqualTo(HttpStatus.UNAUTHORIZED);

        assertThat(OAuth2ErrorHttpMapper.challengeFor(OAuth2ErrorCode.INVALID_CLIENT, true))
                .contains("Basic realm=\"oauth2\", charset=\"UTF-8\"");
    }

    @Test
    void invalidClientFromTheRequestBodyIs400WithNoChallenge() {
        // The 401 branch exists to answer a failed HTTP authentication attempt. Credentials in
        // the body were not one, so challenging would be misleading.
        assertThat(OAuth2ErrorHttpMapper.statusFor(OAuth2ErrorCode.INVALID_CLIENT, false))
                .isEqualTo(HttpStatus.BAD_REQUEST);

        assertThat(OAuth2ErrorHttpMapper.challengeFor(OAuth2ErrorCode.INVALID_CLIENT, false)).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = OAuth2ErrorCode.class, names = "INVALID_CLIENT", mode = EnumSource.Mode.EXCLUDE)
    void onlyInvalidClientIsEverChallenged(OAuth2ErrorCode code) {
        // A header present on some other failure must not turn that response into a 401.
        assertThat(OAuth2ErrorHttpMapper.statusFor(code, true)).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(OAuth2ErrorHttpMapper.challengeFor(code, true)).isEmpty();
    }
}
