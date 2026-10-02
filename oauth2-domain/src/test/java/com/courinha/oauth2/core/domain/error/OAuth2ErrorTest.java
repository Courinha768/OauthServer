package com.courinha.oauth2.core.domain.error;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * RFC 6749 §5.2 constrains the characters allowed in an error response so that it cannot
 * smuggle control characters or non-ASCII into a client's logs.
 */
class OAuth2ErrorTest {

    @ParameterizedTest
    @ValueSource(strings = {"Client authentication failed", "bad!", "plain", "a[b]c"})
    void acceptsDescriptionsWithinThePermittedSet(String description) {
        assertThatCode(() -> OAuth2Error.of(OAuth2ErrorCode.INVALID_CLIENT, description))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"quote\"here", "back\\slash", "nonéascii", "tab\there"})
    void rejectsDescriptionsOutsideThePermittedSet(String description) {
        assertThatThrownBy(() -> OAuth2Error.of(OAuth2ErrorCode.INVALID_REQUEST, description))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("RFC 6749");
    }

    @Test
    void errorUriPermitsBangButNotSpace() {
        assertThatCode(() -> new OAuth2Error(OAuth2ErrorCode.INVALID_REQUEST, null,
                "https://example.com/errors!x"))
                .doesNotThrowAnyException();

        assertThatThrownBy(() -> new OAuth2Error(OAuth2ErrorCode.INVALID_REQUEST, null,
                "https://example.com/a b"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("error_uri");
    }

    @Test
    void descriptionAndUriAreOptional() {
        OAuth2Error error = OAuth2Error.of(OAuth2ErrorCode.INVALID_SCOPE);

        assertThat(error.description()).isNull();
        assertThat(error.errorUri()).isNull();
    }

    @Test
    void wireValuesMatchTheRfcSpelling() {
        assertThat(OAuth2ErrorCode.INVALID_REQUEST.wireValue()).isEqualTo("invalid_request");
        assertThat(OAuth2ErrorCode.INVALID_CLIENT.wireValue()).isEqualTo("invalid_client");
        assertThat(OAuth2ErrorCode.INVALID_GRANT.wireValue()).isEqualTo("invalid_grant");
        assertThat(OAuth2ErrorCode.UNAUTHORIZED_CLIENT.wireValue()).isEqualTo("unauthorized_client");
        assertThat(OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE.wireValue()).isEqualTo("unsupported_grant_type");
        assertThat(OAuth2ErrorCode.INVALID_SCOPE.wireValue()).isEqualTo("invalid_scope");
    }

    /**
     * {@code server_error} belongs to §4.1.2.1 (the authorization endpoint) and must not be
     * offered as a token-endpoint code.
     */
    @Test
    void doesNotOfferAuthorizationEndpointOnlyCodes() {
        assertThat(OAuth2ErrorCode.values())
                .extracting(Enum::name)
                .doesNotContain("SERVER_ERROR", "TEMPORARILY_UNAVAILABLE", "ACCESS_DENIED")
                .hasSize(6);
    }
}
